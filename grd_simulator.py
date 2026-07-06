#!/usr/bin/env python3
"""GRD / DSO simulator for SmartGridReady-compliant Energy Management Systems.

A standalone program that plays the role of a grid operator (French: GRD —
Gestionnaire de Réseau de Distribution; German: VNB — Verteilnetzbetreiber;
Italian: DSO — Distributore di rete) and pushes SmartGridReady grid signals
to a target EMS over HTTP, then visualises the EMS's reactions and ACK/NACK
responses in a small embedded web UI.

Originally built by Teleia (casasmooth — https://www.casasmooth.com) to test
casasmooth's SGr grid-signal webhook, and released here as a free-standing,
reusable tool under the MIT license (see LICENSE). It is a pure HTTP client:
nothing from casasmooth is imported or required, and nothing is installed on
the target — this is an external black-box test harness.

It talks to the target purely over HTTP, using the same contract casasmooth
implements (any EMS speaking this contract can be tested with this tool):

    GRD → EMS   POST   /api/sgr/grid-signal   (Bearer webhook token)
                DELETE /api/sgr/grid-signal   (cancel)
    EMS → GRD   POST   <callback_url>          (ACK/NACK after evaluation)
    observe     GET    /api/sgr/grid-signal    (active signals)
                GET    /api/sgr/audit          (actions taken / skipped)
                GET    /api/sgr/claims         (devices the EMS controls)

See README.md for the full API contract, payload shapes and setup guide.

──────────────────────────────────────────────────────────────────────────
Usage
──────────────────────────────────────────────────────────────────────────

    python3 grd_simulator.py \
        --target http://<ems-host>:<port> \
        --token  <sgr_webhook_token> \
        --port   8770 \
        --lang   en

Then open http://localhost:8770 in a browser. ``--lang`` selects the UI
and event-log language (fr/en/de/it, default fr) for this run — restart
with a different value to switch. GET endpoints (active signal / audit /
claims) are public so polling works even without a token; only
sending/cancelling needs one.

Note: casasmooth (and most EMS implementations) evaluate SGr rules on a
periodic cycle (e.g. every 5 minutes), so device reactions and the ACK/NACK
callback can take a while to appear. The simulator keeps polling and streams
them into the timeline as they arrive.

The SmartGridReady name and logo motif are property of the SmartGridReady
association; the badge rendered here is a simple stylised representation for
demonstration only.

Copyright (c) 2026 Teleia SaRL — MIT License, see LICENSE.
"""

from __future__ import annotations

import argparse
import json
import socket
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional

LANGS = ("fr", "en", "de", "it")
DEFAULT_LANG = "fr"

# ──────────────────────────────────────────────────────────────────────────
# I18N — content dictionaries (fr/en/de/it). A single run serves ONE
# language end to end (UI + server-generated event log), chosen at startup
# via --lang. There is no in-browser language switch: the event log is
# rendered server-side into plain strings when each event happens, so a
# live client-side switch would leave historical entries in the old
# language — restart with a different --lang instead.
# ──────────────────────────────────────────────────────────────────────────

# SG-Ready 2-bit operating states (DE: Betriebszustand). "EVU" (German:
# Elektrizitäts-Versorgungs-Unternehmen / utility) is the term used by the
# SG-Ready spec itself for state 1 in every market, so it is kept untranslated.
SG_READY_LABELS: Dict[str, Dict[int, str]] = {
    "fr": {
        1: "État 1 — Blocage EVU (arrêt forcé, max 2 h/j)",
        2: "État 2 — Fonctionnement réduit (économie)",
        3: "État 3 — Fonctionnement recommandé (normal+)",
        4: "État 4 — Démarrage forcé (surplus / suroffre)",
    },
    "en": {
        1: "State 1 — EVU lock-out (forced stop, max 2 h/day)",
        2: "State 2 — Reduced operation (energy saving)",
        3: "State 3 — Recommended operation (normal+)",
        4: "State 4 — Forced start (surplus / oversupply)",
    },
    "de": {
        1: "Zustand 1 — EVU-Sperre (Zwangsabschaltung, max. 2 Std/Tag)",
        2: "Zustand 2 — Eingeschränkter Betrieb (Energiesparen)",
        3: "Zustand 3 — Empfohlener Betrieb (normal+)",
        4: "Zustand 4 — Erzwungener Einschaltbefehl (Überschuss / Überangebot)",
    },
    "it": {
        1: "Stato 1 — Blocco EVU (arresto forzato, max 2 h/giorno)",
        2: "Stato 2 — Funzionamento ridotto (risparmio energetico)",
        3: "Stato 3 — Funzionamento raccomandato (normale+)",
        4: "Stato 4 — Avvio forzato (surplus / sovrapproduzione)",
    },
}

SIGNAL_TYPE_LABELS: Dict[str, Dict[str, str]] = {
    "fr": {
        "sg_ready": "SG-Ready (état 1–4)",
        "load_reduction": "Délestage (kW max)",
        "tariff": "Tarif dynamique (CHF/kWh)",
        "frequency": "Fréquence réseau (Hz)",
    },
    "en": {
        "sg_ready": "SG-Ready (state 1-4)",
        "load_reduction": "Load shedding (max kW)",
        "tariff": "Dynamic tariff (CHF/kWh)",
        "frequency": "Grid frequency (Hz)",
    },
    "de": {
        "sg_ready": "SG-Ready (Zustand 1-4)",
        "load_reduction": "Lastabwurf (max. kW)",
        "tariff": "Dynamischer Tarif (CHF/kWh)",
        "frequency": "Netzfrequenz (Hz)",
    },
    "it": {
        "sg_ready": "SG-Ready (stato 1-4)",
        "load_reduction": "Distacco carico (kW max)",
        "tariff": "Tariffa dinamica (CHF/kWh)",
        "frequency": "Frequenza di rete (Hz)",
    },
}

# Scripted scenarios for the automatic event generator. Each scenario is an
# ordered list of grid signals the simulator emits one step at a time (one
# every "interval" seconds). duration_seconds is filled in by the runner from
# the step interval if absent, so a step naturally expires once superseded.
SCENARIOS_BY_LANG: Dict[str, Dict[str, Dict[str, Any]]] = {
    "fr": {
        "journee": {
            "label": "Journée type (nuit → matin → midi → soir)",
            "steps": [
                {"signal_type": "tariff", "value": 0.05, "priority": 55,
                 "reason": "Nuit — tarif bas, consommation encouragée"},
                {"signal_type": "sg_ready", "value": 1, "priority": 90,
                 "reason": "Pic matinal 07–09h — blocage EVU"},
                {"signal_type": "sg_ready", "value": 4, "priority": 75,
                 "reason": "Midi — surplus PV, démarrage forcé des charges"},
                {"signal_type": "sg_ready", "value": 1, "priority": 92,
                 "reason": "Pic du soir 18–20h — blocage EVU"},
                {"signal_type": "sg_ready", "value": 3, "priority": 50,
                 "reason": "Soirée — fonctionnement normal recommandé"},
            ],
        },
        "pic_soir": {
            "label": "Montée de pic du soir (3 → 2 → 1)",
            "steps": [
                {"signal_type": "sg_ready", "value": 3, "priority": 50,
                 "reason": "17h — conditions normales"},
                {"signal_type": "sg_ready", "value": 2, "priority": 70,
                 "reason": "18h — charge réseau élevée, mode réduit"},
                {"signal_type": "sg_ready", "value": 1, "priority": 92,
                 "reason": "19h — pic critique, blocage EVU"},
                {"signal_type": "sg_ready", "value": 3, "priority": 50,
                 "reason": "21h — retour à la normale"},
            ],
        },
        "surplus_pv": {
            "label": "Journée ensoleillée (surplus PV variable)",
            "steps": [
                {"signal_type": "sg_ready", "value": 3, "priority": 50,
                 "reason": "Matin — production qui monte"},
                {"signal_type": "sg_ready", "value": 4, "priority": 75,
                 "reason": "Surplus PV — absorber l'excédent"},
                {"signal_type": "tariff", "value": 0.04, "priority": 60,
                 "reason": "Suroffre solaire — prix très bas"},
                {"signal_type": "sg_ready", "value": 4, "priority": 80,
                 "reason": "Pic de production — démarrage forcé"},
                {"signal_type": "sg_ready", "value": 3, "priority": 50,
                 "reason": "Fin de journée — production qui baisse"},
            ],
        },
        "delestage": {
            "label": "Contrainte réseau (délestage progressif)",
            "steps": [
                {"signal_type": "load_reduction", "value": 6, "priority": 80,
                 "reason": "Contrainte réseau locale — plafond 6 kW"},
                {"signal_type": "load_reduction", "value": 3, "priority": 88,
                 "reason": "Aggravation — plafond 3 kW"},
                {"signal_type": "frequency", "value": 49.8, "priority": 95,
                 "reason": "Sous-fréquence réseau — réduction d'urgence"},
                {"signal_type": "load_reduction", "value": 9, "priority": 70,
                 "reason": "Détente — plafond 9 kW"},
                {"signal_type": "sg_ready", "value": 3, "priority": 50,
                 "reason": "Réseau stabilisé — normal"},
            ],
        },
        "stress": {
            "label": "Test de stress (états alternés rapides)",
            "steps": [
                {"signal_type": "sg_ready", "value": 4, "priority": 80, "reason": "Stress — surplus"},
                {"signal_type": "sg_ready", "value": 1, "priority": 90, "reason": "Stress — blocage"},
                {"signal_type": "sg_ready", "value": 2, "priority": 70, "reason": "Stress — réduit"},
                {"signal_type": "sg_ready", "value": 3, "priority": 50, "reason": "Stress — normal"},
            ],
        },
    },
    "en": {
        "journee": {
            "label": "Typical day (night → morning → noon → evening)",
            "steps": [
                {"signal_type": "tariff", "value": 0.05, "priority": 55,
                 "reason": "Night — low tariff, consumption encouraged"},
                {"signal_type": "sg_ready", "value": 1, "priority": 90,
                 "reason": "Morning peak 07-09h — EVU lock-out"},
                {"signal_type": "sg_ready", "value": 4, "priority": 75,
                 "reason": "Noon — PV surplus, forced start of loads"},
                {"signal_type": "sg_ready", "value": 1, "priority": 92,
                 "reason": "Evening peak 18-20h — EVU lock-out"},
                {"signal_type": "sg_ready", "value": 3, "priority": 50,
                 "reason": "Evening — recommended normal operation"},
            ],
        },
        "pic_soir": {
            "label": "Evening peak ramp-up (3 → 2 → 1)",
            "steps": [
                {"signal_type": "sg_ready", "value": 3, "priority": 50, "reason": "5pm — normal conditions"},
                {"signal_type": "sg_ready", "value": 2, "priority": 70, "reason": "6pm — high grid load, reduced mode"},
                {"signal_type": "sg_ready", "value": 1, "priority": 92, "reason": "7pm — critical peak, EVU lock-out"},
                {"signal_type": "sg_ready", "value": 3, "priority": 50, "reason": "9pm — back to normal"},
            ],
        },
        "surplus_pv": {
            "label": "Sunny day (variable PV surplus)",
            "steps": [
                {"signal_type": "sg_ready", "value": 3, "priority": 50, "reason": "Morning — rising production"},
                {"signal_type": "sg_ready", "value": 4, "priority": 75, "reason": "PV surplus — absorb the excess"},
                {"signal_type": "tariff", "value": 0.04, "priority": 60, "reason": "Solar oversupply — very low price"},
                {"signal_type": "sg_ready", "value": 4, "priority": 80, "reason": "Production peak — forced start"},
                {"signal_type": "sg_ready", "value": 3, "priority": 50, "reason": "End of day — declining production"},
            ],
        },
        "delestage": {
            "label": "Grid constraint (progressive load shedding)",
            "steps": [
                {"signal_type": "load_reduction", "value": 6, "priority": 80, "reason": "Local grid constraint — 6 kW cap"},
                {"signal_type": "load_reduction", "value": 3, "priority": 88, "reason": "Worsening — 3 kW cap"},
                {"signal_type": "frequency", "value": 49.8, "priority": 95, "reason": "Grid under-frequency — emergency reduction"},
                {"signal_type": "load_reduction", "value": 9, "priority": 70, "reason": "Easing — 9 kW cap"},
                {"signal_type": "sg_ready", "value": 3, "priority": 50, "reason": "Grid stabilised — normal"},
            ],
        },
        "stress": {
            "label": "Stress test (fast alternating states)",
            "steps": [
                {"signal_type": "sg_ready", "value": 4, "priority": 80, "reason": "Stress — surplus"},
                {"signal_type": "sg_ready", "value": 1, "priority": 90, "reason": "Stress — lock-out"},
                {"signal_type": "sg_ready", "value": 2, "priority": 70, "reason": "Stress — reduced"},
                {"signal_type": "sg_ready", "value": 3, "priority": 50, "reason": "Stress — normal"},
            ],
        },
    },
    "de": {
        "journee": {
            "label": "Typischer Tag (Nacht → Morgen → Mittag → Abend)",
            "steps": [
                {"signal_type": "tariff", "value": 0.05, "priority": 55,
                 "reason": "Nacht — niedriger Tarif, Verbrauch wird gefördert"},
                {"signal_type": "sg_ready", "value": 1, "priority": 90,
                 "reason": "Morgenspitze 07-09 Uhr — EVU-Sperre"},
                {"signal_type": "sg_ready", "value": 4, "priority": 75,
                 "reason": "Mittag — PV-Überschuss, Zwangseinschaltung der Verbraucher"},
                {"signal_type": "sg_ready", "value": 1, "priority": 92,
                 "reason": "Abendspitze 18-20 Uhr — EVU-Sperre"},
                {"signal_type": "sg_ready", "value": 3, "priority": 50,
                 "reason": "Abend — empfohlener Normalbetrieb"},
            ],
        },
        "pic_soir": {
            "label": "Anstieg der Abendspitze (3 → 2 → 1)",
            "steps": [
                {"signal_type": "sg_ready", "value": 3, "priority": 50, "reason": "17 Uhr — normale Bedingungen"},
                {"signal_type": "sg_ready", "value": 2, "priority": 70, "reason": "18 Uhr — hohe Netzlast, reduzierter Modus"},
                {"signal_type": "sg_ready", "value": 1, "priority": 92, "reason": "19 Uhr — kritische Spitze, EVU-Sperre"},
                {"signal_type": "sg_ready", "value": 3, "priority": 50, "reason": "21 Uhr — Rückkehr zum Normalbetrieb"},
            ],
        },
        "surplus_pv": {
            "label": "Sonniger Tag (variabler PV-Überschuss)",
            "steps": [
                {"signal_type": "sg_ready", "value": 3, "priority": 50, "reason": "Morgen — steigende Produktion"},
                {"signal_type": "sg_ready", "value": 4, "priority": 75, "reason": "PV-Überschuss — Überschuss aufnehmen"},
                {"signal_type": "tariff", "value": 0.04, "priority": 60, "reason": "Solares Überangebot — sehr niedriger Preis"},
                {"signal_type": "sg_ready", "value": 4, "priority": 80, "reason": "Produktionsspitze — Zwangseinschaltung"},
                {"signal_type": "sg_ready", "value": 3, "priority": 50, "reason": "Tagesende — sinkende Produktion"},
            ],
        },
        "delestage": {
            "label": "Netzengpass (progressiver Lastabwurf)",
            "steps": [
                {"signal_type": "load_reduction", "value": 6, "priority": 80, "reason": "Lokaler Netzengpass — Obergrenze 6 kW"},
                {"signal_type": "load_reduction", "value": 3, "priority": 88, "reason": "Verschärfung — Obergrenze 3 kW"},
                {"signal_type": "frequency", "value": 49.8, "priority": 95, "reason": "Netzunterfrequenz — Notabsenkung"},
                {"signal_type": "load_reduction", "value": 9, "priority": 70, "reason": "Entspannung — Obergrenze 9 kW"},
                {"signal_type": "sg_ready", "value": 3, "priority": 50, "reason": "Netz stabilisiert — normal"},
            ],
        },
        "stress": {
            "label": "Stresstest (schnell wechselnde Zustände)",
            "steps": [
                {"signal_type": "sg_ready", "value": 4, "priority": 80, "reason": "Stress — Überschuss"},
                {"signal_type": "sg_ready", "value": 1, "priority": 90, "reason": "Stress — Sperre"},
                {"signal_type": "sg_ready", "value": 2, "priority": 70, "reason": "Stress — reduziert"},
                {"signal_type": "sg_ready", "value": 3, "priority": 50, "reason": "Stress — normal"},
            ],
        },
    },
    "it": {
        "journee": {
            "label": "Giornata tipo (notte → mattina → mezzogiorno → sera)",
            "steps": [
                {"signal_type": "tariff", "value": 0.05, "priority": 55,
                 "reason": "Notte — tariffa bassa, consumo incoraggiato"},
                {"signal_type": "sg_ready", "value": 1, "priority": 90,
                 "reason": "Picco mattutino 07-09h — blocco EVU"},
                {"signal_type": "sg_ready", "value": 4, "priority": 75,
                 "reason": "Mezzogiorno — surplus FV, avvio forzato dei carichi"},
                {"signal_type": "sg_ready", "value": 1, "priority": 92,
                 "reason": "Picco serale 18-20h — blocco EVU"},
                {"signal_type": "sg_ready", "value": 3, "priority": 50,
                 "reason": "Sera — funzionamento normale raccomandato"},
            ],
        },
        "pic_soir": {
            "label": "Salita del picco serale (3 → 2 → 1)",
            "steps": [
                {"signal_type": "sg_ready", "value": 3, "priority": 50, "reason": "17h — condizioni normali"},
                {"signal_type": "sg_ready", "value": 2, "priority": 70, "reason": "18h — carico di rete elevato, modalità ridotta"},
                {"signal_type": "sg_ready", "value": 1, "priority": 92, "reason": "19h — picco critico, blocco EVU"},
                {"signal_type": "sg_ready", "value": 3, "priority": 50, "reason": "21h — ritorno alla normalità"},
            ],
        },
        "surplus_pv": {
            "label": "Giornata soleggiata (surplus FV variabile)",
            "steps": [
                {"signal_type": "sg_ready", "value": 3, "priority": 50, "reason": "Mattina — produzione in aumento"},
                {"signal_type": "sg_ready", "value": 4, "priority": 75, "reason": "Surplus FV — assorbire l'eccedenza"},
                {"signal_type": "tariff", "value": 0.04, "priority": 60, "reason": "Sovrapproduzione solare — prezzo molto basso"},
                {"signal_type": "sg_ready", "value": 4, "priority": 80, "reason": "Picco di produzione — avvio forzato"},
                {"signal_type": "sg_ready", "value": 3, "priority": 50, "reason": "Fine giornata — produzione in calo"},
            ],
        },
        "delestage": {
            "label": "Vincolo di rete (distacco carico progressivo)",
            "steps": [
                {"signal_type": "load_reduction", "value": 6, "priority": 80, "reason": "Vincolo di rete locale — limite 6 kW"},
                {"signal_type": "load_reduction", "value": 3, "priority": 88, "reason": "Aggravamento — limite 3 kW"},
                {"signal_type": "frequency", "value": 49.8, "priority": 95, "reason": "Sottofrequenza di rete — riduzione d'emergenza"},
                {"signal_type": "load_reduction", "value": 9, "priority": 70, "reason": "Allentamento — limite 9 kW"},
                {"signal_type": "sg_ready", "value": 3, "priority": 50, "reason": "Rete stabilizzata — normale"},
            ],
        },
        "stress": {
            "label": "Test di stress (stati alternati rapidi)",
            "steps": [
                {"signal_type": "sg_ready", "value": 4, "priority": 80, "reason": "Stress — surplus"},
                {"signal_type": "sg_ready", "value": 1, "priority": 90, "reason": "Stress — blocco"},
                {"signal_type": "sg_ready", "value": 2, "priority": 70, "reason": "Stress — ridotto"},
                {"signal_type": "sg_ready", "value": 3, "priority": 50, "reason": "Stress — normale"},
            ],
        },
    },
}

# Quick one-click presets shown in the sidebar.
PRESETS_BY_LANG: Dict[str, List[Dict[str, Any]]] = {
    "fr": [
        {"t": "Surplus PV / suroffre", "d": "SG-Ready état 4 — démarrer les charges",
         "sig": {"signal_type": "sg_ready", "value": 4, "priority": 75, "duration_seconds": 3600,
                 "reason": "Suroffre solaire — absorber le surplus"}},
        {"t": "Pic de demande", "d": "SG-Ready état 1 — blocage EVU",
         "sig": {"signal_type": "sg_ready", "value": 1, "priority": 90, "duration_seconds": 1800,
                 "reason": "Pic de demande réseau — délestage"}},
        {"t": "Fonctionnement réduit", "d": "SG-Ready état 2",
         "sig": {"signal_type": "sg_ready", "value": 2, "priority": 60, "duration_seconds": 3600,
                 "reason": "Charge réseau élevée — mode réduit"}},
        {"t": "Normal recommandé", "d": "SG-Ready état 3",
         "sig": {"signal_type": "sg_ready", "value": 3, "priority": 50, "duration_seconds": 3600,
                 "reason": "Conditions favorables"}},
        {"t": "Délestage 3 kW", "d": "load_reduction — plafond d'import",
         "sig": {"signal_type": "load_reduction", "value": 3, "priority": 85, "duration_seconds": 1800,
                 "reason": "Contrainte réseau locale 3 kW"}},
        {"t": "Tarif bas 0.05", "d": "tariff — incite la consommation",
         "sig": {"signal_type": "tariff", "value": 0.05, "priority": 55, "duration_seconds": 3600,
                 "reason": "Fenêtre tarifaire basse"}},
        {"t": "Tarif haut 0.42", "d": "tariff — incite l'effacement",
         "sig": {"signal_type": "tariff", "value": 0.42, "priority": 70, "duration_seconds": 3600,
                 "reason": "Fenêtre tarifaire haute"}},
        {"t": "Sous-fréquence", "d": "frequency 49.8 Hz — réduire",
         "sig": {"signal_type": "frequency", "value": 49.8, "priority": 95, "duration_seconds": 900,
                 "reason": "Sous-fréquence réseau"}},
    ],
    "en": [
        {"t": "PV surplus / oversupply", "d": "SG-Ready state 4 — start loads",
         "sig": {"signal_type": "sg_ready", "value": 4, "priority": 75, "duration_seconds": 3600,
                 "reason": "Solar oversupply — absorb the surplus"}},
        {"t": "Demand peak", "d": "SG-Ready state 1 — EVU lock-out",
         "sig": {"signal_type": "sg_ready", "value": 1, "priority": 90, "duration_seconds": 1800,
                 "reason": "Grid demand peak — load shedding"}},
        {"t": "Reduced operation", "d": "SG-Ready state 2",
         "sig": {"signal_type": "sg_ready", "value": 2, "priority": 60, "duration_seconds": 3600,
                 "reason": "High grid load — reduced mode"}},
        {"t": "Recommended normal", "d": "SG-Ready state 3",
         "sig": {"signal_type": "sg_ready", "value": 3, "priority": 50, "duration_seconds": 3600,
                 "reason": "Favourable conditions"}},
        {"t": "Load shedding 3 kW", "d": "load_reduction — import cap",
         "sig": {"signal_type": "load_reduction", "value": 3, "priority": 85, "duration_seconds": 1800,
                 "reason": "Local grid constraint 3 kW"}},
        {"t": "Low tariff 0.05", "d": "tariff — encourages consumption",
         "sig": {"signal_type": "tariff", "value": 0.05, "priority": 55, "duration_seconds": 3600,
                 "reason": "Low-tariff window"}},
        {"t": "High tariff 0.42", "d": "tariff — encourages load shifting",
         "sig": {"signal_type": "tariff", "value": 0.42, "priority": 70, "duration_seconds": 3600,
                 "reason": "High-tariff window"}},
        {"t": "Under-frequency", "d": "frequency 49.8 Hz — reduce",
         "sig": {"signal_type": "frequency", "value": 49.8, "priority": 95, "duration_seconds": 900,
                 "reason": "Grid under-frequency"}},
    ],
    "de": [
        {"t": "PV-Überschuss / Überangebot", "d": "SG-Ready Zustand 4 — Verbraucher einschalten",
         "sig": {"signal_type": "sg_ready", "value": 4, "priority": 75, "duration_seconds": 3600,
                 "reason": "Solares Überangebot — Überschuss aufnehmen"}},
        {"t": "Nachfragespitze", "d": "SG-Ready Zustand 1 — EVU-Sperre",
         "sig": {"signal_type": "sg_ready", "value": 1, "priority": 90, "duration_seconds": 1800,
                 "reason": "Netznachfragespitze — Lastabwurf"}},
        {"t": "Eingeschränkter Betrieb", "d": "SG-Ready Zustand 2",
         "sig": {"signal_type": "sg_ready", "value": 2, "priority": 60, "duration_seconds": 3600,
                 "reason": "Hohe Netzlast — reduzierter Modus"}},
        {"t": "Empfohlen normal", "d": "SG-Ready Zustand 3",
         "sig": {"signal_type": "sg_ready", "value": 3, "priority": 50, "duration_seconds": 3600,
                 "reason": "Günstige Bedingungen"}},
        {"t": "Lastabwurf 3 kW", "d": "load_reduction — Bezugsobergrenze",
         "sig": {"signal_type": "load_reduction", "value": 3, "priority": 85, "duration_seconds": 1800,
                 "reason": "Lokaler Netzengpass 3 kW"}},
        {"t": "Niedriger Tarif 0.05", "d": "tariff — fördert Verbrauch",
         "sig": {"signal_type": "tariff", "value": 0.05, "priority": 55, "duration_seconds": 3600,
                 "reason": "Niedertarif-Fenster"}},
        {"t": "Hoher Tarif 0.42", "d": "tariff — fördert Lastverschiebung",
         "sig": {"signal_type": "tariff", "value": 0.42, "priority": 70, "duration_seconds": 3600,
                 "reason": "Hochtarif-Fenster"}},
        {"t": "Unterfrequenz", "d": "frequency 49.8 Hz — reduzieren",
         "sig": {"signal_type": "frequency", "value": 49.8, "priority": 95, "duration_seconds": 900,
                 "reason": "Netzunterfrequenz"}},
    ],
    "it": [
        {"t": "Surplus FV / sovrapproduzione", "d": "SG-Ready stato 4 — avviare i carichi",
         "sig": {"signal_type": "sg_ready", "value": 4, "priority": 75, "duration_seconds": 3600,
                 "reason": "Sovrapproduzione solare — assorbire il surplus"}},
        {"t": "Picco di domanda", "d": "SG-Ready stato 1 — blocco EVU",
         "sig": {"signal_type": "sg_ready", "value": 1, "priority": 90, "duration_seconds": 1800,
                 "reason": "Picco di domanda di rete — distacco carico"}},
        {"t": "Funzionamento ridotto", "d": "SG-Ready stato 2",
         "sig": {"signal_type": "sg_ready", "value": 2, "priority": 60, "duration_seconds": 3600,
                 "reason": "Carico di rete elevato — modalità ridotta"}},
        {"t": "Normale raccomandato", "d": "SG-Ready stato 3",
         "sig": {"signal_type": "sg_ready", "value": 3, "priority": 50, "duration_seconds": 3600,
                 "reason": "Condizioni favorevoli"}},
        {"t": "Distacco carico 3 kW", "d": "load_reduction — limite di prelievo",
         "sig": {"signal_type": "load_reduction", "value": 3, "priority": 85, "duration_seconds": 1800,
                 "reason": "Vincolo di rete locale 3 kW"}},
        {"t": "Tariffa bassa 0.05", "d": "tariff — incentiva il consumo",
         "sig": {"signal_type": "tariff", "value": 0.05, "priority": 55, "duration_seconds": 3600,
                 "reason": "Finestra tariffaria bassa"}},
        {"t": "Tariffa alta 0.42", "d": "tariff — incentiva il rinvio dei carichi",
         "sig": {"signal_type": "tariff", "value": 0.42, "priority": 70, "duration_seconds": 3600,
                 "reason": "Finestra tariffaria alta"}},
        {"t": "Sottofrequenza", "d": "frequency 49.8 Hz — ridurre",
         "sig": {"signal_type": "frequency", "value": 49.8, "priority": 95, "duration_seconds": 900,
                 "reason": "Sottofrequenza di rete"}},
    ],
}

# Server-generated event-log message templates (Python str.format placeholders).
EVT: Dict[str, Dict[str, str]] = {
    "fr": {
        "auto_started_title": "Mode automatique démarré : {label}",
        "auto_started_detail": "pas toutes les {interval}s · {mode}",
        "mode_loop": "en boucle", "mode_once": "une fois",
        "auto_stopped": "Mode automatique arrêté",
        "signal_sent_title": "Signal émis : {human}",
        "signal_sent_detail": "priorité {priority} · TTL {ttl}s · source {source}",
        "send_failed_title": "Échec d'émission ({status})",
        "cancel_ok_title": "Signal(aux) annulé(s)",
        "cancel_ok_one": " : {signal_id}", "cancel_ok_all": " (tous)",
        "cancel_failed_title": "Échec d'annulation ({status})",
        "poll_error_title": "Erreur de polling",
        "auto_error_title": "Erreur en mode automatique",
        "scenario_finished_title": "Scénario automatique terminé",
        "sim_started_title": "Simulateur GRD démarré",
        "sim_started_detail": "cible {target} · callback {callback}",
        "observe_title": "Mode observation (cs_sgr_enabled OFF) : {n} action(s) prise(s) en compte, NON appliquée(s)",
        "applied_title": "L'EMS a appliqué {n} action(s) aux devices SGr",
        "deferred_title": "Pris en compte mais différé : {n} action(s) non appliquée(s)",
        "deferred_suffix": " (hystérésis / déjà à la valeur)",
        "signal_seen_title": "Signal {type}={value} vu — aucune règle SGr concernée",
        "signal_seen_detail": "{n} règle(s) non déclenchée(s)",
        "cb_applied": "l'optimiseur a commandé un device SGr",
        "cb_observed_only": "mode observation — pris en compte, rien envoyé",
        "cb_deferred": "pris en compte mais différé (hystérésis / déjà à la valeur)",
        "cb_received_not_applied": "aucun device SGr concerné",
        "cb_unknown": "callback : {status}",
        "humanise_load_reduction": "Délestage à {val} kW max",
        "humanise_tariff": "Signal tarifaire {val} CHF/kWh",
        "humanise_frequency": "Fréquence {val} Hz",
        "sg_ready_fallback": "SG-Ready={val}",
    },
    "en": {
        "auto_started_title": "Automatic mode started: {label}",
        "auto_started_detail": "step every {interval}s · {mode}",
        "mode_loop": "looping", "mode_once": "once",
        "auto_stopped": "Automatic mode stopped",
        "signal_sent_title": "Signal sent: {human}",
        "signal_sent_detail": "priority {priority} · TTL {ttl}s · source {source}",
        "send_failed_title": "Send failed ({status})",
        "cancel_ok_title": "Signal(s) cancelled",
        "cancel_ok_one": ": {signal_id}", "cancel_ok_all": " (all)",
        "cancel_failed_title": "Cancel failed ({status})",
        "poll_error_title": "Polling error",
        "auto_error_title": "Error in automatic mode",
        "scenario_finished_title": "Automatic scenario finished",
        "sim_started_title": "GRD simulator started",
        "sim_started_detail": "target {target} · callback {callback}",
        "observe_title": "Observe-only mode (cs_sgr_enabled OFF): {n} action(s) considered, NOT applied",
        "applied_title": "The EMS applied {n} action(s) to SGr devices",
        "deferred_title": "Considered but deferred: {n} action(s) not applied",
        "deferred_suffix": " (hysteresis / already at value)",
        "signal_seen_title": "Signal {type}={value} seen — no SGr rule concerned",
        "signal_seen_detail": "{n} rule(s) not triggered",
        "cb_applied": "optimiser commanded an SGr device",
        "cb_observed_only": "observe-only mode — considered, nothing sent",
        "cb_deferred": "considered but deferred (hysteresis / already at value)",
        "cb_received_not_applied": "no SGr device concerned",
        "cb_unknown": "callback: {status}",
        "humanise_load_reduction": "Load shedding at {val} kW max",
        "humanise_tariff": "Tariff signal {val} CHF/kWh",
        "humanise_frequency": "Frequency {val} Hz",
        "sg_ready_fallback": "SG-Ready={val}",
    },
    "de": {
        "auto_started_title": "Automatikmodus gestartet: {label}",
        "auto_started_detail": "Schritt alle {interval}s · {mode}",
        "mode_loop": "wiederholend", "mode_once": "einmalig",
        "auto_stopped": "Automatikmodus gestoppt",
        "signal_sent_title": "Signal gesendet: {human}",
        "signal_sent_detail": "Priorität {priority} · TTL {ttl}s · Quelle {source}",
        "send_failed_title": "Senden fehlgeschlagen ({status})",
        "cancel_ok_title": "Signal(e) abgebrochen",
        "cancel_ok_one": ": {signal_id}", "cancel_ok_all": " (alle)",
        "cancel_failed_title": "Abbruch fehlgeschlagen ({status})",
        "poll_error_title": "Abfragefehler",
        "auto_error_title": "Fehler im Automatikmodus",
        "scenario_finished_title": "Automatisches Szenario beendet",
        "sim_started_title": "VNB-Simulator gestartet",
        "sim_started_detail": "Ziel {target} · Callback {callback}",
        "observe_title": "Beobachtungsmodus (cs_sgr_enabled AUS): {n} Aktion(en) berücksichtigt, NICHT angewendet",
        "applied_title": "Das EMS hat {n} Aktion(en) auf SGr-Geräte angewendet",
        "deferred_title": "Berücksichtigt, aber aufgeschoben: {n} Aktion(en) nicht angewendet",
        "deferred_suffix": " (Hysterese / bereits auf Wert)",
        "signal_seen_title": "Signal {type}={value} gesehen — keine SGr-Regel betroffen",
        "signal_seen_detail": "{n} Regel(n) nicht ausgelöst",
        "cb_applied": "Optimierer hat ein SGr-Gerät angesteuert",
        "cb_observed_only": "Beobachtungsmodus — berücksichtigt, nichts gesendet",
        "cb_deferred": "berücksichtigt, aber aufgeschoben (Hysterese / bereits auf Wert)",
        "cb_received_not_applied": "kein SGr-Gerät betroffen",
        "cb_unknown": "Callback: {status}",
        "humanise_load_reduction": "Lastabwurf auf max. {val} kW",
        "humanise_tariff": "Tarifsignal {val} CHF/kWh",
        "humanise_frequency": "Frequenz {val} Hz",
        "sg_ready_fallback": "SG-Ready={val}",
    },
    "it": {
        "auto_started_title": "Modalità automatica avviata: {label}",
        "auto_started_detail": "passo ogni {interval}s · {mode}",
        "mode_loop": "in ciclo", "mode_once": "una volta",
        "auto_stopped": "Modalità automatica interrotta",
        "signal_sent_title": "Segnale inviato: {human}",
        "signal_sent_detail": "priorità {priority} · TTL {ttl}s · fonte {source}",
        "send_failed_title": "Invio non riuscito ({status})",
        "cancel_ok_title": "Segnale/i annullato/i",
        "cancel_ok_one": ": {signal_id}", "cancel_ok_all": " (tutti)",
        "cancel_failed_title": "Annullamento non riuscito ({status})",
        "poll_error_title": "Errore di polling",
        "auto_error_title": "Errore in modalità automatica",
        "scenario_finished_title": "Scenario automatico terminato",
        "sim_started_title": "Simulatore DSO avviato",
        "sim_started_detail": "destinazione {target} · callback {callback}",
        "observe_title": "Modalità osservazione (cs_sgr_enabled OFF): {n} azione/i considerata/e, NON applicata/e",
        "applied_title": "L'EMS ha applicato {n} azione/i ai dispositivi SGr",
        "deferred_title": "Considerato ma differito: {n} azione/i non applicata/e",
        "deferred_suffix": " (isteresi / già al valore)",
        "signal_seen_title": "Segnale {type}={value} rilevato — nessuna regola SGr coinvolta",
        "signal_seen_detail": "{n} regola/e non attivata/e",
        "cb_applied": "l'ottimizzatore ha comandato un dispositivo SGr",
        "cb_observed_only": "modalità osservazione — considerato, nulla inviato",
        "cb_deferred": "considerato ma differito (isteresi / già al valore)",
        "cb_received_not_applied": "nessun dispositivo SGr coinvolto",
        "cb_unknown": "callback: {status}",
        "humanise_load_reduction": "Distacco carico a {val} kW max",
        "humanise_tariff": "Segnale tariffario {val} CHF/kWh",
        "humanise_frequency": "Frequenza {val} Hz",
        "sg_ready_fallback": "SG-Ready={val}",
    },
}

# Static + dynamic UI text (embedded HTML/JS). Injected once at page-render
# time for the process's --lang; see render_ui_html().
UI_STRINGS: Dict[str, Dict[str, str]] = {
    "fr": {
        "DOC_TITLE": "Simulateur GRD · SmartGridReady",
        "BRAND_SUFFIX": "Simulateur GRD",
        "BRAND_SUB": "Gestionnaire de réseau virtuel → EMS SGr",
        "CONN_CONNECTING": "connexion…", "CONN_ONLINE": "EMS en ligne",
        "CONN_OFFLINE": "EMS injoignable", "CONN_SIM_OFFLINE": "simulateur hors-ligne",
        "EVAL_NOTE": "éval. EMS ≤ 5 min",
        "H_TARGET": "Cible EMS", "LBL_TARGET_URL": "URL de base de l'EMS (host:port)",
        "HINT_TARGET": "Modifiez cette URL pour tester une autre instance, puis « Enregistrer ».",
        "LBL_TOKEN": "Webhook token (envoi/annulation)",
        "LBL_PUBLIC_URL": "URL publique de ce simulateur (pour le callback)",
        "BTN_SAVE_CFG": "Enregistrer &amp; reconnecter",
        "H_AUTO": "Mode automatique (générateur d'évènements GRD)",
        "HINT_AUTO": "Le simulateur émet tout seul une séquence de signaux GRD pour observer les réactions sans cliquer.",
        "LBL_SCENARIO": "Scénario", "LBL_STEP_S": "Pas (s)", "LBL_LOOP": "En boucle",
        "BTN_AUTO_START": "▶ Démarrer", "BTN_AUTO_STOP": "■ Arrêter",
        "H_PRESETS": "Scénarios GRD rapides", "H_CUSTOM": "Signal personnalisé",
        "LBL_SIG_TYPE": "Type de signal", "OPT_SG_READY": "SG-Ready (état 1–4)",
        "OPT_LOAD_REDUCTION": "Délestage (kW max)", "OPT_TARIFF": "Tarif dynamique (CHF/kWh)",
        "OPT_FREQUENCY": "Fréquence réseau (Hz)",
        "LBL_VALUE": "Valeur", "LBL_PRIORITY": "Priorité 0–100",
        "LBL_DURATION": "Durée (s)", "LBL_SOURCE": "Source",
        "LBL_REASON": "Raison (optionnel)", "PLACEHOLDER_REASON": "Pic de demande réseau 18h-20h",
        "BTN_SEND": "⚡ Émettre le signal", "BTN_CANCEL_ALL": "✕ Annuler tous les signaux actifs",
        "LEGEND_GRD": "Action GRD", "LEGEND_CS": "Réaction EMS", "LEGEND_ERR": "Erreur",
        "BTN_REFRESH": "↻ Rafraîchir maintenant",
        "EMPTY_EVENTS": "Aucun évènement pour l'instant. Émettez un signal GRD pour démarrer.",
        "CHIP_TARGET": "Cible", "CHIP_MODE": "Mode optimiseur",
        "MODE_ACTIVE": "actif — applique", "MODE_OBSERVE": "observation (cs_sgr_enabled OFF)",
        "CHIP_ACTIVE_SIGNALS": "Signaux actifs", "CHIP_WINNER": "Signal gagnant",
        "CHIP_CLAIMS": "Appareils pilotés (SGr)", "CHIP_LAST_POLL": "Dernier sondage",
        "CHIP_CLAIMS_TITLE": "Claims SGr",
        "WHO_GRD": "GRD", "WHO_CS": "EMS", "WHO_ERR": "erreur", "WHO_INFO": "info",
        "BADGE_APPLIED": "✓ APPLIQUÉ", "BADGE_OBSERVED": "◐ OBSERVÉ — non appliqué",
        "BADGE_DEFERRED": "○ DIFFÉRÉ — pris en compte, non appliqué", "BADGE_NOT_APPLIED": "○ NON APPLIQUÉ",
        "RAW_DETAILS": "détails techniques",
        "AUTO_RUNNING": "● en cours", "AUTO_STOPPED": "arrêté",
        "AUTO_STEP_WORD": "pas", "AUTO_EVERY_WORD": "toutes les", "AUTO_LOOP_SUFFIX": "boucle",
        "LOCALE": "fr-CH",
    },
    "en": {
        "DOC_TITLE": "GRD Simulator · SmartGridReady",
        "BRAND_SUFFIX": "GRD Simulator",
        "BRAND_SUB": "Virtual grid operator → SGr EMS",
        "CONN_CONNECTING": "connecting…", "CONN_ONLINE": "EMS online",
        "CONN_OFFLINE": "EMS unreachable", "CONN_SIM_OFFLINE": "simulator offline",
        "EVAL_NOTE": "EMS eval ≤ 5 min",
        "H_TARGET": "EMS target", "LBL_TARGET_URL": "EMS base URL (host:port)",
        "HINT_TARGET": "Change this URL to test another instance, then Save.",
        "LBL_TOKEN": "Webhook token (send/cancel)",
        "LBL_PUBLIC_URL": "Public URL of this simulator (for the callback)",
        "BTN_SAVE_CFG": "Save &amp; reconnect",
        "H_AUTO": "Automatic mode (GRD event generator)",
        "HINT_AUTO": "The simulator emits a sequence of GRD signals on its own so you can observe reactions without clicking.",
        "LBL_SCENARIO": "Scenario", "LBL_STEP_S": "Step (s)", "LBL_LOOP": "Loop",
        "BTN_AUTO_START": "▶ Start", "BTN_AUTO_STOP": "■ Stop",
        "H_PRESETS": "Quick GRD scenarios", "H_CUSTOM": "Custom signal",
        "LBL_SIG_TYPE": "Signal type", "OPT_SG_READY": "SG-Ready (state 1-4)",
        "OPT_LOAD_REDUCTION": "Load shedding (max kW)", "OPT_TARIFF": "Dynamic tariff (CHF/kWh)",
        "OPT_FREQUENCY": "Grid frequency (Hz)",
        "LBL_VALUE": "Value", "LBL_PRIORITY": "Priority 0-100",
        "LBL_DURATION": "Duration (s)", "LBL_SOURCE": "Source",
        "LBL_REASON": "Reason (optional)", "PLACEHOLDER_REASON": "Grid demand peak 6-8pm",
        "BTN_SEND": "⚡ Send signal", "BTN_CANCEL_ALL": "✕ Cancel all active signals",
        "LEGEND_GRD": "GRD action", "LEGEND_CS": "EMS reaction", "LEGEND_ERR": "Error",
        "BTN_REFRESH": "↻ Refresh now",
        "EMPTY_EVENTS": "No events yet. Send a GRD signal to get started.",
        "CHIP_TARGET": "Target", "CHIP_MODE": "Optimiser mode",
        "MODE_ACTIVE": "active — applies", "MODE_OBSERVE": "observe-only (cs_sgr_enabled OFF)",
        "CHIP_ACTIVE_SIGNALS": "Active signals", "CHIP_WINNER": "Winning signal",
        "CHIP_CLAIMS": "Devices controlled (SGr)", "CHIP_LAST_POLL": "Last poll",
        "CHIP_CLAIMS_TITLE": "SGr claims",
        "WHO_GRD": "GRD", "WHO_CS": "EMS", "WHO_ERR": "error", "WHO_INFO": "info",
        "BADGE_APPLIED": "✓ APPLIED", "BADGE_OBSERVED": "◐ OBSERVED — not applied",
        "BADGE_DEFERRED": "○ DEFERRED — considered, not applied", "BADGE_NOT_APPLIED": "○ NOT APPLIED",
        "RAW_DETAILS": "technical details",
        "AUTO_RUNNING": "● running", "AUTO_STOPPED": "stopped",
        "AUTO_STEP_WORD": "step", "AUTO_EVERY_WORD": "every", "AUTO_LOOP_SUFFIX": "loop",
        "LOCALE": "en-GB",
    },
    "de": {
        "DOC_TITLE": "VNB-Simulator · SmartGridReady",
        "BRAND_SUFFIX": "VNB-Simulator",
        "BRAND_SUB": "Virtueller Netzbetreiber → SGr-EMS",
        "CONN_CONNECTING": "verbinde…", "CONN_ONLINE": "EMS online",
        "CONN_OFFLINE": "EMS nicht erreichbar", "CONN_SIM_OFFLINE": "Simulator offline",
        "EVAL_NOTE": "EMS-Auswertung ≤ 5 Min",
        "H_TARGET": "EMS-Ziel", "LBL_TARGET_URL": "EMS-Basis-URL (Host:Port)",
        "HINT_TARGET": "Ändern Sie diese URL, um eine andere Instanz zu testen, dann Speichern.",
        "LBL_TOKEN": "Webhook-Token (Senden/Abbrechen)",
        "LBL_PUBLIC_URL": "Öffentliche URL dieses Simulators (für den Callback)",
        "BTN_SAVE_CFG": "Speichern &amp; neu verbinden",
        "H_AUTO": "Automatikmodus (VNB-Ereignisgenerator)",
        "HINT_AUTO": "Der Simulator sendet selbstständig eine Abfolge von VNB-Signalen, damit Sie Reaktionen ohne Klicken beobachten können.",
        "LBL_SCENARIO": "Szenario", "LBL_STEP_S": "Schritt (s)", "LBL_LOOP": "Wiederholen",
        "BTN_AUTO_START": "▶ Starten", "BTN_AUTO_STOP": "■ Stopp",
        "H_PRESETS": "Schnelle VNB-Szenarien", "H_CUSTOM": "Benutzerdefiniertes Signal",
        "LBL_SIG_TYPE": "Signaltyp", "OPT_SG_READY": "SG-Ready (Zustand 1-4)",
        "OPT_LOAD_REDUCTION": "Lastabwurf (max. kW)", "OPT_TARIFF": "Dynamischer Tarif (CHF/kWh)",
        "OPT_FREQUENCY": "Netzfrequenz (Hz)",
        "LBL_VALUE": "Wert", "LBL_PRIORITY": "Priorität 0-100",
        "LBL_DURATION": "Dauer (s)", "LBL_SOURCE": "Quelle",
        "LBL_REASON": "Grund (optional)", "PLACEHOLDER_REASON": "Netznachfragespitze 18-20 Uhr",
        "BTN_SEND": "⚡ Signal senden", "BTN_CANCEL_ALL": "✕ Alle aktiven Signale abbrechen",
        "LEGEND_GRD": "VNB-Aktion", "LEGEND_CS": "EMS-Reaktion", "LEGEND_ERR": "Fehler",
        "BTN_REFRESH": "↻ Jetzt aktualisieren",
        "EMPTY_EVENTS": "Noch keine Ereignisse. Senden Sie ein VNB-Signal, um zu beginnen.",
        "CHIP_TARGET": "Ziel", "CHIP_MODE": "Optimierer-Modus",
        "MODE_ACTIVE": "aktiv — wendet an", "MODE_OBSERVE": "Beobachtung (cs_sgr_enabled AUS)",
        "CHIP_ACTIVE_SIGNALS": "Aktive Signale", "CHIP_WINNER": "Gewinnendes Signal",
        "CHIP_CLAIMS": "Gesteuerte Geräte (SGr)", "CHIP_LAST_POLL": "Letzte Abfrage",
        "CHIP_CLAIMS_TITLE": "SGr-Ansprüche",
        "WHO_GRD": "VNB", "WHO_CS": "EMS", "WHO_ERR": "Fehler", "WHO_INFO": "Info",
        "BADGE_APPLIED": "✓ ANGEWENDET", "BADGE_OBSERVED": "◐ BEOBACHTET — nicht angewendet",
        "BADGE_DEFERRED": "○ AUFGESCHOBEN — berücksichtigt, nicht angewendet", "BADGE_NOT_APPLIED": "○ NICHT ANGEWENDET",
        "RAW_DETAILS": "technische Details",
        "AUTO_RUNNING": "● läuft", "AUTO_STOPPED": "gestoppt",
        "AUTO_STEP_WORD": "Schritt", "AUTO_EVERY_WORD": "alle", "AUTO_LOOP_SUFFIX": "Wiederholung",
        "LOCALE": "de-CH",
    },
    "it": {
        "DOC_TITLE": "Simulatore DSO · SmartGridReady",
        "BRAND_SUFFIX": "Simulatore DSO",
        "BRAND_SUB": "Gestore di rete virtuale → EMS SGr",
        "CONN_CONNECTING": "connessione…", "CONN_ONLINE": "EMS online",
        "CONN_OFFLINE": "EMS non raggiungibile", "CONN_SIM_OFFLINE": "simulatore offline",
        "EVAL_NOTE": "valutazione EMS ≤ 5 min",
        "H_TARGET": "Destinazione EMS", "LBL_TARGET_URL": "URL base dell'EMS (host:porta)",
        "HINT_TARGET": "Modifica questo URL per testare un'altra istanza, poi Salva.",
        "LBL_TOKEN": "Token webhook (invio/annullamento)",
        "LBL_PUBLIC_URL": "URL pubblico di questo simulatore (per il callback)",
        "BTN_SAVE_CFG": "Salva &amp; riconnetti",
        "H_AUTO": "Modalità automatica (generatore di eventi DSO)",
        "HINT_AUTO": "Il simulatore emette da solo una sequenza di segnali DSO per osservare le reazioni senza dover cliccare.",
        "LBL_SCENARIO": "Scenario", "LBL_STEP_S": "Passo (s)", "LBL_LOOP": "Ciclo",
        "BTN_AUTO_START": "▶ Avvia", "BTN_AUTO_STOP": "■ Ferma",
        "H_PRESETS": "Scenari DSO rapidi", "H_CUSTOM": "Segnale personalizzato",
        "LBL_SIG_TYPE": "Tipo di segnale", "OPT_SG_READY": "SG-Ready (stato 1-4)",
        "OPT_LOAD_REDUCTION": "Distacco carico (kW max)", "OPT_TARIFF": "Tariffa dinamica (CHF/kWh)",
        "OPT_FREQUENCY": "Frequenza di rete (Hz)",
        "LBL_VALUE": "Valore", "LBL_PRIORITY": "Priorità 0-100",
        "LBL_DURATION": "Durata (s)", "LBL_SOURCE": "Fonte",
        "LBL_REASON": "Motivo (opzionale)", "PLACEHOLDER_REASON": "Picco di domanda di rete 18-20",
        "BTN_SEND": "⚡ Invia segnale", "BTN_CANCEL_ALL": "✕ Annulla tutti i segnali attivi",
        "LEGEND_GRD": "Azione DSO", "LEGEND_CS": "Reazione EMS", "LEGEND_ERR": "Errore",
        "BTN_REFRESH": "↻ Aggiorna ora",
        "EMPTY_EVENTS": "Nessun evento per ora. Invia un segnale DSO per iniziare.",
        "CHIP_TARGET": "Destinazione", "CHIP_MODE": "Modalità ottimizzatore",
        "MODE_ACTIVE": "attivo — applica", "MODE_OBSERVE": "osservazione (cs_sgr_enabled OFF)",
        "CHIP_ACTIVE_SIGNALS": "Segnali attivi", "CHIP_WINNER": "Segnale vincente",
        "CHIP_CLAIMS": "Dispositivi controllati (SGr)", "CHIP_LAST_POLL": "Ultimo sondaggio",
        "CHIP_CLAIMS_TITLE": "Claims SGr",
        "WHO_GRD": "DSO", "WHO_CS": "EMS", "WHO_ERR": "errore", "WHO_INFO": "info",
        "BADGE_APPLIED": "✓ APPLICATO", "BADGE_OBSERVED": "◐ OSSERVATO — non applicato",
        "BADGE_DEFERRED": "○ DIFFERITO — considerato, non applicato", "BADGE_NOT_APPLIED": "○ NON APPLICATO",
        "RAW_DETAILS": "dettagli tecnici",
        "AUTO_RUNNING": "● in corso", "AUTO_STOPPED": "fermato",
        "AUTO_STEP_WORD": "passo", "AUTO_EVERY_WORD": "ogni", "AUTO_LOOP_SUFFIX": "ciclo",
        "LOCALE": "it-CH",
    },
}


def _lang_or_default(lang: Optional[str]) -> str:
    return lang if lang in LANGS else DEFAULT_LANG


# ──────────────────────────────────────────────────────────────────────────
# Shared, thread-safe simulator state
# ──────────────────────────────────────────────────────────────────────────


class SimState:
    """In-memory state shared between the HTTP handler threads and the poller."""

    def __init__(self, target: str, token: str, public_url: str, lang: str = DEFAULT_LANG) -> None:
        self.lock = threading.Lock()
        self.target = target.rstrip("/")
        self.token = token
        self.public_url = public_url.rstrip("/")
        self.lang = _lang_or_default(lang)
        self.events: List[Dict[str, Any]] = []
        self.sent_signals: Dict[str, Dict[str, Any]] = {}
        self.last_audit_ts: Optional[str] = None
        self.auto: Dict[str, Any] = {
            "running": False,
            "scenario": None,
            "interval": 60,
            "loop": True,
            "index": 0,
            "next_at": 0.0,
        }
        self.last_poll: Dict[str, Any] = {
            "active": [],
            "claims": [],
            "audit": [],
            "ok": False,
            "error": None,
            "at": None,
        }
        self._seq = 0

    # -- events ------------------------------------------------------------

    def add_event(self, side: str, kind: str, title: str,
                  detail: str = "", data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        with self.lock:
            self._seq += 1
            ev = {
                "id": self._seq,
                "ts": datetime.now(timezone.utc).isoformat(),
                "side": side,          # "grd" | "cs" | "info"
                "kind": kind,          # send | cancel | callback | reaction | poll | error
                "title": title,
                "detail": detail,
                "data": data or {},
            }
            self.events.append(ev)
            if len(self.events) > 500:
                self.events = self.events[-500:]
            return ev

    def snapshot(self) -> Dict[str, Any]:
        with self.lock:
            scenarios = SCENARIOS_BY_LANG.get(self.lang, SCENARIOS_BY_LANG[DEFAULT_LANG])
            return {
                "target": self.target,
                "public_url": self.public_url,
                "has_token": bool(self.token),
                "lang": self.lang,
                "events": list(self.events),
                "sent_signals": dict(self.sent_signals),
                "last_poll": dict(self.last_poll),
                "auto": dict(self.auto),
                "scenarios": [{"value": k, "label": v["label"],
                               "steps": len(v["steps"])}
                              for k, v in scenarios.items()],
            }

    def set_config(self, target: Optional[str], token: Optional[str],
                   public_url: Optional[str]) -> None:
        with self.lock:
            if target is not None:
                new_target = target.rstrip("/")
                if new_target and new_target != self.target:
                    # Switched to a different EMS instance: forget the
                    # previous instance's audit baseline so its recent activity
                    # is read fresh, and drop the stale poll snapshot.
                    self.target = new_target
                    self.last_audit_ts = None
                    self.last_poll = {"active": [], "claims": [], "audit": [],
                                      "ok": False, "error": None, "at": None,
                                      "status_codes": {}}
                    self.auto["running"] = False
            if token is not None:
                self.token = token
            if public_url is not None:
                self.public_url = public_url.rstrip("/")

    # -- automatic scenario player ----------------------------------------

    def start_auto(self, scenario: str, interval: float, loop: bool) -> Dict[str, Any]:
        scenarios = SCENARIOS_BY_LANG.get(self.lang, SCENARIOS_BY_LANG[DEFAULT_LANG])
        if scenario not in scenarios:
            return {"ok": False, "error": f"unknown scenario '{scenario}'"}
        txt = EVT[self.lang]
        with self.lock:
            self.auto.update({
                "running": True, "scenario": scenario,
                "interval": max(5.0, float(interval)), "loop": bool(loop),
                "index": 0, "next_at": time.time(),
            })
        interval_i = int(max(5.0, float(interval)))
        mode = txt["mode_loop"] if loop else txt["mode_once"]
        self.add_event(
            "info", "info",
            txt["auto_started_title"].format(label=scenarios[scenario]["label"]),
            txt["auto_started_detail"].format(interval=interval_i, mode=mode),
        )
        return {"ok": True}

    def stop_auto(self) -> Dict[str, Any]:
        with self.lock:
            was = self.auto["running"]
            self.auto["running"] = False
        if was:
            self.add_event("info", "info", EVT[self.lang]["auto_stopped"], "")
        return {"ok": True}


# ──────────────────────────────────────────────────────────────────────────
# EMS API client (stdlib only)
# ──────────────────────────────────────────────────────────────────────────


def _http_json(method: str, url: str, token: Optional[str] = None,
               body: Optional[Dict[str, Any]] = None, timeout: float = 8.0):
    """Perform an HTTP request, returning (status_code, parsed_json_or_text)."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, raw
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace") if exc.fp else ""
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, raw or str(exc)
    except (urllib.error.URLError, socket.timeout, OSError) as exc:
        return 0, str(getattr(exc, "reason", exc))


# ──────────────────────────────────────────────────────────────────────────
# Signal sending / cancelling
# ──────────────────────────────────────────────────────────────────────────


def humanise_signal(sig: Dict[str, Any], lang: str) -> str:
    txt = EVT.get(lang, EVT[DEFAULT_LANG])
    labels = SG_READY_LABELS.get(lang, SG_READY_LABELS[DEFAULT_LANG])
    st = sig.get("signal_type")
    val = sig.get("value")
    if st == "sg_ready":
        try:
            return labels.get(int(val), txt["sg_ready_fallback"].format(val=val))
        except (TypeError, ValueError):
            return txt["sg_ready_fallback"].format(val=val)
    if st == "load_reduction":
        return txt["humanise_load_reduction"].format(val=val)
    if st == "tariff":
        return txt["humanise_tariff"].format(val=val)
    if st == "frequency":
        return txt["humanise_frequency"].format(val=val)
    return f"{st}={val}"


def send_signal(state: SimState, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Push a grid signal to the target EMS and record it."""
    snap = state.snapshot()
    target = snap["target"]
    token = state.token
    public_url = snap["public_url"]
    txt = EVT.get(state.lang, EVT[DEFAULT_LANG])

    # Correlate the callback with this signal via a query param we control.
    corr = uuid.uuid4().hex[:8]
    callback_url = f"{public_url}/api/callback?corr={corr}" if public_url else None

    body = {
        "signal_type": payload["signal_type"],
        "value": float(payload["value"]),
        "source": payload.get("source", "grd-simulator"),
        "duration_seconds": int(payload.get("duration_seconds", 1800)),
        "priority": int(payload.get("priority", 60)),
        "reason": payload.get("reason") or f"GRD simulator {corr}",
    }
    if callback_url:
        body["callback_url"] = callback_url

    status, resp = _http_json("POST", f"{target}/api/sgr/grid-signal",
                              token=token, body=body)

    human = humanise_signal(body, state.lang)
    if status in (200, 201) and isinstance(resp, dict):
        signal_id = resp.get("signal_id", corr)
        with state.lock:
            state.sent_signals[corr] = {
                "corr": corr,
                "signal_id": signal_id,
                "body": body,
                "human": human,
                "status": "sent",
                "sent_at": datetime.now(timezone.utc).isoformat(),
            }
        state.add_event(
            "grd", "send",
            txt["signal_sent_title"].format(human=human),
            txt["signal_sent_detail"].format(
                priority=body["priority"], ttl=body["duration_seconds"], source=body["source"]),
            {"request": body, "response": resp, "corr": corr,
             "signal_id": signal_id},
        )
        return {"ok": True, "signal_id": signal_id, "corr": corr,
                "response": resp}

    state.add_event(
        "error", "error",
        txt["send_failed_title"].format(status=status),
        json.dumps(resp) if not isinstance(resp, str) else resp,
        {"request": body, "status": status, "response": resp},
    )
    return {"ok": False, "status": status, "response": resp}


def cancel_signals(state: SimState, signal_id: Optional[str] = None) -> Dict[str, Any]:
    snap = state.snapshot()
    target = snap["target"]
    txt = EVT.get(state.lang, EVT[DEFAULT_LANG])
    url = f"{target}/api/sgr/grid-signal"
    if signal_id:
        url += f"?signal_id={signal_id}"
    status, resp = _http_json("DELETE", url, token=state.token)
    if status == 200:
        suffix = txt["cancel_ok_one"].format(signal_id=signal_id) if signal_id else txt["cancel_ok_all"]
        state.add_event(
            "grd", "cancel",
            txt["cancel_ok_title"] + suffix,
            json.dumps(resp) if isinstance(resp, dict) else str(resp),
            {"response": resp},
        )
        return {"ok": True, "response": resp}
    state.add_event(
        "error", "error", txt["cancel_failed_title"].format(status=status),
        str(resp), {"status": status, "response": resp},
    )
    return {"ok": False, "status": status, "response": resp}


# ──────────────────────────────────────────────────────────────────────────
# Background poller — observes EMS reactions
# ──────────────────────────────────────────────────────────────────────────


def poll_ems(state: SimState) -> None:
    """Fetch active signals, audit log and claims; stream new reactions."""
    target = state.snapshot()["target"]
    txt = EVT.get(state.lang, EVT[DEFAULT_LANG])

    s1, active = _http_json("GET", f"{target}/api/sgr/grid-signal")
    s2, audit = _http_json("GET", f"{target}/api/sgr/audit?limit=8")
    s3, claims = _http_json("GET", f"{target}/api/sgr/claims")

    ok = s1 == 200
    error = None if ok else (active if isinstance(active, str) else json.dumps(active))

    active_list = active.get("all_signals", []) if isinstance(active, dict) else []
    audit_entries = audit.get("entries", []) if isinstance(audit, dict) else []
    claim_list = claims.get("claims", []) if isinstance(claims, dict) else []

    # Detect newly-added audit entries (newest first from the API) and surface
    # the ones that reacted to a grid signal as EMS reactions.
    new_entries: List[Dict[str, Any]] = []
    with state.lock:
        last_ts = state.last_audit_ts
    for entry in reversed(audit_entries):  # oldest → newest
        ts = entry.get("timestamp")
        if not ts:
            continue
        if last_ts is None or ts > last_ts:
            new_entries.append(entry)

    for entry in new_entries:
        ctx = entry.get("context", {})
        details = entry.get("details", []) or []
        skipped = entry.get("skipped", []) or []
        observed = entry.get("observed", []) or []
        apply_enabled = entry.get("apply_enabled", True)
        grid_active = ctx.get("grid_signal_active")
        gtype = ctx.get("grid_signal_type")
        gval = ctx.get("grid_signal_value")

        # Deferred = a rule reacted but was held back (hysteresis / already set);
        # distinct from "no_condition_matched" which means no rule cared.
        deferred = [s for s in skipped if s.get("reason") in ("hysteresis", "already_set")]

        def _fmt(items):
            return ", ".join(f"{i.get('rule', '?')}→{i.get('value')}" for i in items)

        if not apply_enabled and observed:
            # Observe-only mode: optimiser DID take the signal into account but
            # cs_sgr_enabled is OFF so nothing was sent to the devices.
            state.add_event(
                "cs", "reaction",
                txt["observe_title"].format(n=len(observed)),
                _fmt(observed),
                {"context": _slim_ctx(ctx), "observed": observed,
                 "skipped": skipped, "apply_enabled": False},
            )
        elif details:
            # Applied: commands actually written to devices.
            state.add_event(
                "cs", "reaction",
                txt["applied_title"].format(n=len(details)),
                _fmt(details),
                {"context": _slim_ctx(ctx), "details": details,
                 "skipped": skipped, "apply_enabled": apply_enabled},
            )
        elif deferred:
            # Considered but held back.
            state.add_event(
                "cs", "reaction",
                txt["deferred_title"].format(n=len(deferred)),
                _fmt(deferred) + txt["deferred_suffix"],
                {"context": _slim_ctx(ctx), "skipped": skipped,
                 "apply_enabled": apply_enabled},
            )
        elif grid_active:
            # Signal seen, but no rule reacted to it.
            state.add_event(
                "cs", "reaction",
                txt["signal_seen_title"].format(type=gtype, value=gval),
                txt["signal_seen_detail"].format(n=len(skipped)),
                {"context": _slim_ctx(ctx), "skipped": skipped,
                 "apply_enabled": apply_enabled},
            )

    if audit_entries:
        newest_ts = audit_entries[0].get("timestamp")
        with state.lock:
            if newest_ts and (state.last_audit_ts is None
                              or newest_ts > state.last_audit_ts):
                state.last_audit_ts = newest_ts

    # Current optimiser mode (active vs observe-only) from the newest audit entry.
    mode_apply_enabled = True
    if audit_entries:
        mode_apply_enabled = audit_entries[0].get("apply_enabled", True)

    with state.lock:
        state.last_poll = {
            "active": active_list,
            "claims": claim_list,
            "audit": audit_entries[:5],
            "ok": ok,
            "error": error,
            "apply_enabled": mode_apply_enabled,
            "at": datetime.now(timezone.utc).isoformat(),
            "status_codes": {"signal": s1, "audit": s2, "claims": s3},
        }


def _slim_ctx(ctx: Dict[str, Any]) -> Dict[str, Any]:
    keys = ("spot_price", "pv_power", "surplus_pv", "battery_soc",
            "grid_signal_active", "grid_signal_type", "grid_signal_value",
            "is_peak", "is_offpeak", "house_consumption")
    return {k: ctx.get(k) for k in keys if k in ctx}


def poller_loop(state: SimState, interval: float, stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            poll_ems(state)
        except Exception as exc:  # never die
            state.add_event("error", "error", EVT[state.lang]["poll_error_title"], str(exc))
        stop.wait(interval)


def auto_loop(state: SimState, stop: threading.Event) -> None:
    """Drive the automatic scenario player: emit one grid event per interval."""
    while not stop.is_set():
        with state.lock:
            auto = dict(state.auto)
        if auto["running"] and auto["scenario"] and time.time() >= auto["next_at"]:
            scenarios = SCENARIOS_BY_LANG.get(state.lang, SCENARIOS_BY_LANG[DEFAULT_LANG])
            scenario = scenarios.get(auto["scenario"])
            steps = scenario["steps"] if scenario else []
            if steps:
                idx = auto["index"]
                interval = auto["interval"]
                step = dict(steps[idx % len(steps)])
                step.setdefault("duration_seconds", int(max(120, interval * 2)))
                step.setdefault("source", "grd-simulator-auto")
                try:
                    send_signal(state, step)
                except Exception as exc:
                    state.add_event("error", "error", EVT[state.lang]["auto_error_title"], str(exc))
                new_idx = idx + 1
                finished = (not auto["loop"]) and new_idx >= len(steps)
                with state.lock:
                    state.auto["index"] = new_idx
                    state.auto["next_at"] = time.time() + interval
                    if finished:
                        state.auto["running"] = False
                if finished:
                    state.add_event("info", "info",
                                    EVT[state.lang]["scenario_finished_title"],
                                    scenario["label"])
        stop.wait(1.0)


# ──────────────────────────────────────────────────────────────────────────
# HTTP request handler (serves UI + simulator API + EMS callback sink)
# ──────────────────────────────────────────────────────────────────────────


class Handler(BaseHTTPRequestHandler):
    state: SimState = None  # injected
    ui_html: str = ""       # injected (pre-rendered for the process's --lang)
    server_version = "GRDSim/1.0"

    def log_message(self, fmt, *args):  # quieter logs
        pass

    # -- helpers -----------------------------------------------------------

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj: Any) -> None:
        self._send(code, json.dumps(obj).encode("utf-8"), "application/json")

    def _read_body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", 0) or 0)
        if not length:
            return {}
        raw = self.rfile.read(length).decode("utf-8", "replace")
        try:
            return json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return {}

    def _query(self) -> Dict[str, str]:
        if "?" not in self.path:
            return {}
        from urllib.parse import parse_qs, urlparse
        q = urlparse(self.path).query
        return {k: v[0] for k, v in parse_qs(q).items()}

    # -- routing -----------------------------------------------------------

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/" or path == "/index.html":
            self._send(200, self.ui_html.encode("utf-8"), "text/html; charset=utf-8")
        elif path == "/api/state":
            self._json(200, self.state.snapshot())
        elif path == "/api/poll-now":
            try:
                poll_ems(self.state)
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
                return
            self._json(200, {"ok": True, "last_poll": self.state.snapshot()["last_poll"]})
        elif path == "/health":
            self._json(200, {"ok": True})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path == "/api/send":
            body = self._read_body()
            if not body.get("signal_type"):
                self._json(400, {"ok": False, "error": "signal_type required"})
                return
            self._json(200, send_signal(self.state, body))
        elif path == "/api/cancel":
            body = self._read_body()
            self._json(200, cancel_signals(self.state, body.get("signal_id")))
        elif path == "/api/config":
            body = self._read_body()
            self.state.set_config(body.get("target"), body.get("token"),
                                  body.get("public_url"))
            self._json(200, {"ok": True, "snapshot": self.state.snapshot()})
        elif path == "/api/auto/start":
            body = self._read_body()
            res = self.state.start_auto(
                body.get("scenario", ""),
                body.get("interval", 60),
                body.get("loop", True),
            )
            self._json(200 if res.get("ok") else 400, res)
        elif path == "/api/auto/stop":
            self._json(200, self.state.stop_auto())
        elif path == "/api/callback":
            # The target EMS POSTs its ACK/NACK here after evaluating the signal.
            corr = self._query().get("corr")
            body = self._read_body()
            self._handle_callback(corr, body)
            self._json(200, {"ok": True})
        else:
            self._json(404, {"error": "not found"})

    def do_DELETE(self):
        if self.path.split("?", 1)[0] == "/api/cancel":
            self._json(200, cancel_signals(self.state, self._query().get("signal_id")))
        else:
            self._json(404, {"error": "not found"})

    # -- callback handling -------------------------------------------------

    def _handle_callback(self, corr: Optional[str], body: Dict[str, Any]) -> None:
        txt = EVT.get(self.state.lang, EVT[DEFAULT_LANG])
        status = body.get("status", "?")
        actions = body.get("actions", []) or []
        considered = bool(body.get("considered"))
        applied = status == "applied"
        apply_enabled = body.get("apply_enabled", True)
        human = ""
        with self.state.lock:
            rec = self.state.sent_signals.get(corr) if corr else None
            if rec:
                rec["status"] = status
                rec["callback"] = body
                human = rec.get("human", "")
        # Distinct, unambiguous titles for each outcome:
        #   applied            → optimiser took it into account AND commanded a device
        #   observed_only      → took it into account but cs_sgr_enabled=OFF → nothing sent
        #   deferred           → took it into account but held back (hysteresis / already set)
        #   received_not_applied → no device cares about this signal
        if status == "applied":
            title = txt["cb_applied"]
        elif status == "observed_only":
            title = txt["cb_observed_only"]
        elif status == "deferred":
            title = txt["cb_deferred"]
        elif status == "received_not_applied":
            title = txt["cb_received_not_applied"]
        else:
            title = txt["cb_unknown"].format(status=status)
        detail = body.get("detail") or human
        if human and body.get("detail"):
            detail = f"{human} — {detail}"
        if actions:
            detail += " — " + ", ".join(
                f"{a.get('rule', '?')}→{a.get('value')}" for a in actions)
        self.state.add_event(
            "cs", "callback", title, detail,
            {
                "callback": body, "corr": corr,
                "applied": applied, "considered": considered,
                "apply_enabled": apply_enabled, "status": status,
            },
        )


# ──────────────────────────────────────────────────────────────────────────
# Embedded web UI (template with __TOKEN__ placeholders, rendered once per
# process for the chosen --lang — see render_ui_html()).
# ──────────────────────────────────────────────────────────────────────────

UI_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="__HTML_LANG__">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>__DOC_TITLE__</title>
<style>
  :root{
    --sgr-green:#8DC63F; --sgr-green-d:#5a9216; --grd:#1f6feb; --cs:#16a34a;
    --bg:#0e1117; --panel:#161b22; --panel2:#1c2230; --line:#2b3240;
    --txt:#e6edf3; --muted:#9aa6b2; --warn:#f0b429; --err:#f85149;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--txt);
       font-family:"Segoe UI",Roboto,system-ui,sans-serif;font-size:14px}
  header{display:flex;align-items:center;gap:16px;padding:14px 20px;
         background:linear-gradient(90deg,#11161d,#161b22);
         border-bottom:1px solid var(--line)}
  .logo{display:flex;align-items:center;gap:10px}
  .logo .name{font-weight:700;font-size:18px;letter-spacing:.2px}
  .logo .name b{color:var(--sgr-green)}
  .logo .sub{color:var(--muted);font-size:12px}
  .spacer{flex:1}
  .pill{padding:4px 10px;border-radius:999px;font-size:12px;border:1px solid var(--line);
        background:var(--panel2);color:var(--muted)}
  .pill.ok{color:#7ee787;border-color:#2ea04366}
  .pill.bad{color:var(--err);border-color:#f8514966}
  main{display:grid;grid-template-columns:340px 1fr;gap:0;height:calc(100vh - 61px)}
  aside{border-right:1px solid var(--line);padding:16px;overflow:auto;background:var(--panel)}
  section.feed{padding:16px 20px;overflow:auto}
  h2{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);
     margin:18px 0 8px}
  h2:first-child{margin-top:0}
  .field{margin-bottom:10px}
  label{display:block;font-size:12px;color:var(--muted);margin-bottom:4px}
  input,select,textarea{width:100%;background:var(--panel2);border:1px solid var(--line);
        color:var(--txt);border-radius:8px;padding:8px 10px;font-size:13px}
  textarea{resize:vertical;min-height:48px}
  .row{display:flex;gap:8px}
  .row>*{flex:1}
  button{cursor:pointer;border:none;border-radius:8px;padding:9px 12px;font-weight:600;
         font-size:13px;background:var(--panel2);color:var(--txt);border:1px solid var(--line)}
  button:hover{border-color:var(--sgr-green)}
  button.primary{background:var(--sgr-green);color:#10260a;border-color:var(--sgr-green)}
  button.primary:hover{background:#9bd64f}
  button.danger{color:var(--err);border-color:#f8514955}
  button.danger:hover{background:#3a1414}
  .presets{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:6px}
  .preset{font-size:12px;text-align:left;padding:10px;line-height:1.3}
  .preset .t{display:block;font-weight:700;margin-bottom:2px}
  .preset .d{display:block;color:var(--muted);font-weight:400}
  .legend{display:flex;gap:14px;align-items:center;margin-bottom:10px;color:var(--muted);font-size:12px}
  .dot{width:9px;height:9px;border-radius:50%;display:inline-block;margin-right:5px}
  .dot.grd{background:var(--grd)} .dot.cs{background:var(--cs)} .dot.err{background:var(--err)}
  .timeline{position:relative;margin-left:0}
  .ev{display:grid;grid-template-columns:120px 1fr;gap:14px;padding:10px 0;
      border-bottom:1px dashed var(--line)}
  .ev .when{color:var(--muted);font-size:12px;font-variant-numeric:tabular-nums}
  .card{border-radius:10px;padding:11px 13px;border:1px solid var(--line);background:var(--panel)}
  .card.grd{border-left:4px solid var(--grd)}
  .card.cs{border-left:4px solid var(--cs)}
  .card.info{border-left:4px solid var(--muted)}
  .card.err{border-left:4px solid var(--err)}
  .card .who{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);
             margin-bottom:3px}
  .card .ttl{font-weight:650}
  .card .dtl{color:var(--muted);margin-top:4px;font-size:13px;white-space:pre-wrap}
  .card .applied{color:#7ee787;font-weight:700}
  .card .notapplied{color:var(--warn);font-weight:700}
  .card .observed{color:#79c0ff;font-weight:700}
  details.raw{margin-top:6px}
  details.raw summary{cursor:pointer;color:var(--muted);font-size:12px}
  details.raw pre{background:#0b0f14;border:1px solid var(--line);border-radius:8px;
        padding:8px;overflow:auto;font-size:11.5px;max-height:240px;margin:6px 0 0}
  .statusbar{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:14px}
  .chip{background:var(--panel);border:1px solid var(--line);border-radius:10px;
        padding:8px 12px;min-width:120px}
  .chip .k{font-size:11px;color:var(--muted)} .chip .v{font-weight:700;font-size:16px;margin-top:2px}
  .muted{color:var(--muted)} .small{font-size:12px}
  .hint{color:var(--muted);font-size:11.5px;margin:-2px 0 10px;line-height:1.4}
  .claims{display:flex;flex-wrap:wrap;gap:6px;margin-top:4px}
  .claims .c{background:var(--panel2);border:1px solid var(--line);border-radius:999px;
             padding:3px 9px;font-size:12px}
  .empty{color:var(--muted);text-align:center;padding:40px 0}
</style>
</head>
<body>
<header>
  <div class="logo">
    <!-- Stylised SmartGridReady badge -->
    <svg width="38" height="38" viewBox="0 0 64 64" aria-label="SmartGridReady">
      <rect x="2" y="2" width="60" height="60" rx="14" fill="#10260a"
            stroke="#8DC63F" stroke-width="2"/>
      <g stroke="#8DC63F" stroke-width="2.4" fill="none" stroke-linecap="round">
        <path d="M14 40 L24 28 L34 36 L50 18"/>
        <path d="M50 18 L50 27" /><path d="M50 18 L41 18"/>
      </g>
      <g fill="#8DC63F">
        <circle cx="14" cy="40" r="3.2"/><circle cx="24" cy="28" r="3.2"/>
        <circle cx="34" cy="36" r="3.2"/><circle cx="50" cy="18" r="3.2"/>
      </g>
      <path d="M30 46 l-5 10 h5 l-3 6" stroke="#8DC63F" stroke-width="2.2"
            fill="none" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
    <div>
      <div class="name">Smart<b>GridReady</b> · __BRAND_SUFFIX__</div>
      <div class="sub">__BRAND_SUB__</div>
    </div>
  </div>
  <div class="spacer"></div>
  <span id="conn" class="pill">__CONN_CONNECTING__</span>
  <span id="evalNote" class="pill">__EVAL_NOTE__</span>
</header>

<main>
  <aside>
    <h2>__H_TARGET__</h2>
    <div class="field"><label>__LBL_TARGET_URL__</label>
      <input id="target" placeholder="http://192.168.1.10:28100"/></div>
    <div class="hint">__HINT_TARGET__</div>
    <div class="field"><label>__LBL_TOKEN__</label>
      <input id="token" type="password" placeholder="sgr_webhook_token"/></div>
    <div class="field"><label>__LBL_PUBLIC_URL__</label>
      <input id="public_url" placeholder="http://192.168.1.20:8770"/></div>
    <button id="saveCfg" style="width:100%">__BTN_SAVE_CFG__</button>

    <h2>__H_AUTO__</h2>
    <div class="hint">__HINT_AUTO__</div>
    <div class="field"><label>__LBL_SCENARIO__</label>
      <select id="auto_scenario"></select></div>
    <div class="row">
      <div class="field"><label>__LBL_STEP_S__</label><input id="auto_interval" value="60"/></div>
      <div class="field"><label><input type="checkbox" id="auto_loop" checked/> __LBL_LOOP__</label></div>
    </div>
    <div class="row">
      <button id="autoStart" class="primary" style="flex:1">__BTN_AUTO_START__</button>
      <button id="autoStop" class="danger" style="flex:1">__BTN_AUTO_STOP__</button>
    </div>
    <div id="autoStatus" class="hint" style="margin-top:6px"></div>

    <h2>__H_PRESETS__</h2>
    <div class="presets" id="presets"></div>

    <h2>__H_CUSTOM__</h2>
    <div class="field"><label>__LBL_SIG_TYPE__</label>
      <select id="sig_type">
        <option value="sg_ready">__OPT_SG_READY__</option>
        <option value="load_reduction">__OPT_LOAD_REDUCTION__</option>
        <option value="tariff">__OPT_TARIFF__</option>
        <option value="frequency">__OPT_FREQUENCY__</option>
      </select></div>
    <div class="row">
      <div class="field"><label>__LBL_VALUE__</label><input id="sig_value" value="4"/></div>
      <div class="field"><label>__LBL_PRIORITY__</label><input id="sig_prio" value="70"/></div>
    </div>
    <div class="row">
      <div class="field"><label>__LBL_DURATION__</label><input id="sig_ttl" value="1800"/></div>
      <div class="field"><label>__LBL_SOURCE__</label><input id="sig_src" value="grd-simulator"/></div>
    </div>
    <div class="field"><label>__LBL_REASON__</label>
      <textarea id="sig_reason" placeholder="__PLACEHOLDER_REASON__"></textarea></div>
    <button id="sendBtn" class="primary" style="width:100%">__BTN_SEND__</button>
    <button id="cancelBtn" class="danger" style="width:100%;margin-top:8px">__BTN_CANCEL_ALL__</button>
  </aside>

  <section class="feed">
    <div class="statusbar" id="statusbar"></div>
    <div class="legend">
      <span><i class="dot grd"></i>__LEGEND_GRD__</span>
      <span><i class="dot cs"></i>__LEGEND_CS__</span>
      <span><i class="dot err"></i>__LEGEND_ERR__</span>
      <span class="spacer"></span>
      <button id="refreshBtn" class="small">__BTN_REFRESH__</button>
    </div>
    <div class="timeline" id="timeline"><div class="empty">__EMPTY_EVENTS__</div></div>
  </section>
</main>

<script>
const I18N = __I18N_JSON__;
const PRESETS = __PRESETS_JSON__;

const $ = (id)=>document.getElementById(id);
let lastSeenId = 0;

function fmtTime(iso){
  try{const d=new Date(iso);return d.toLocaleTimeString(I18N.LOCALE,{hour12:false})+
    '.'+String(d.getMilliseconds()).padStart(3,'0').slice(0,2);}catch(e){return iso;}
}
function esc(s){return (s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}

function renderPresets(){
  $('presets').innerHTML='';
  PRESETS.forEach(p=>{
    const b=document.createElement('button');
    b.className='preset';
    b.innerHTML=`<span class="t">${esc(p.t)}</span><span class="d">${esc(p.d)}</span>`;
    b.onclick=()=>send(p.sig);
    $('presets').appendChild(b);
  });
}

async function api(path, opts){
  const r = await fetch(path, opts);
  return r.json();
}

async function send(sig){
  await api('/api/send',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify(sig)});
  await refresh();
}

$('sendBtn').onclick=()=>{
  send({
    signal_type:$('sig_type').value,
    value:parseFloat($('sig_value').value),
    priority:parseInt($('sig_prio').value||'60'),
    duration_seconds:parseInt($('sig_ttl').value||'1800'),
    source:$('sig_src').value||'grd-simulator',
    reason:$('sig_reason').value||null,
  });
};
$('cancelBtn').onclick=async()=>{
  await api('/api/cancel',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
  await refresh();
};
$('saveCfg').onclick=async()=>{
  await api('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({target:$('target').value,token:$('token').value,
      public_url:$('public_url').value})});
  await api('/api/poll-now');
  await refresh();
};
let scenariosRendered=false;
function renderScenarios(snap){
  const sel=$('auto_scenario');
  if(!scenariosRendered && (snap.scenarios||[]).length){
    sel.innerHTML='';
    snap.scenarios.forEach(s=>{
      const o=document.createElement('option');
      o.value=s.value; o.textContent=s.label+' ('+s.steps+')';
      sel.appendChild(o);
    });
    scenariosRendered=true;
  }
  const a=snap.auto||{};
  const st=$('autoStatus');
  if(a.running){
    const sc=(snap.scenarios||[]).find(x=>x.value===a.scenario);
    const total=sc?sc.steps:'?';
    st.innerHTML='<b style="color:var(--sgr-green)">'+I18N.AUTO_RUNNING+'</b> · '+
      esc(a.scenario)+' · '+I18N.AUTO_STEP_WORD+' '+(a.index)+'/'+total+' · '+
      I18N.AUTO_EVERY_WORD+' '+a.interval+'s'+
      (a.loop?' · '+I18N.AUTO_LOOP_SUFFIX:'');
  } else {
    st.textContent=I18N.AUTO_STOPPED;
  }
}
$('autoStart').onclick=async()=>{
  await api('/api/auto/start',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({scenario:$('auto_scenario').value,
      interval:parseInt($('auto_interval').value||'60'),
      loop:$('auto_loop').checked})});
  await refresh();
};
$('autoStop').onclick=async()=>{
  await api('/api/auto/stop',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
  await refresh();
};
$('refreshBtn').onclick=async()=>{ await api('/api/poll-now'); await refresh(); };

function renderStatus(snap){
  const lp = snap.last_poll||{};
  const conn=$('conn');
  if(lp.ok){conn.textContent=I18N.CONN_ONLINE;conn.className='pill ok';}
  else{conn.textContent=I18N.CONN_OFFLINE;conn.className='pill bad';}

  const active = lp.active||[]; const claims=lp.claims||[];
  const winner = active[0];
  const sb=$('statusbar');
  sb.innerHTML='';
  const chip=(k,v)=>`<div class="chip"><div class="k">${esc(k)}</div><div class="v">${v}</div></div>`;
  const tgt=(snap.target||'').replace(/^https?:\/\//,'');
  sb.innerHTML += chip(I18N.CHIP_TARGET, esc(tgt||'—'));
  const applyEnabled = (lp.apply_enabled!==false);
  const modeTxt = applyEnabled
    ? '<span style="color:#7ee787">'+I18N.MODE_ACTIVE+'</span>'
    : '<span style="color:#79c0ff">'+I18N.MODE_OBSERVE+'</span>';
  sb.innerHTML += chip(I18N.CHIP_MODE, modeTxt);
  sb.innerHTML += chip(I18N.CHIP_ACTIVE_SIGNALS, active.length);
  sb.innerHTML += chip(I18N.CHIP_WINNER, winner? esc(winner.signal_type+'='+winner.value):'—');
  sb.innerHTML += chip(I18N.CHIP_CLAIMS, claims.length);
  const lastAt = lp.at? fmtTime(lp.at):'—';
  sb.innerHTML += chip(I18N.CHIP_LAST_POLL, lastAt);
  if(claims.length){
    let cdiv = '<div class="chip" style="flex:1"><div class="k">'+I18N.CHIP_CLAIMS_TITLE+'</div><div class="claims">';
    claims.forEach(c=>{const n=(typeof c==='string')?c:(c.consumer||c.device||JSON.stringify(c));
      cdiv+=`<span class="c">${esc(n)}</span>`;});
    cdiv+='</div></div>'; sb.innerHTML+=cdiv;
  }
}

function renderEvents(snap){
  const tl=$('timeline');
  const evs=(snap.events||[]).slice().reverse();
  if(!evs.length){tl.innerHTML='<div class="empty">'+I18N.EMPTY_EVENTS+'</div>';return;}
  tl.innerHTML='';
  evs.forEach(ev=>{
    const side = ev.side==='grd'?'grd':ev.side==='cs'?'cs':ev.side==='error'?'err':'info';
    const who = ev.side==='grd'?I18N.WHO_GRD:ev.side==='cs'?I18N.WHO_CS:ev.side==='error'?I18N.WHO_ERR:I18N.WHO_INFO;
    let ttlHtml = esc(ev.title);
    if(ev.kind==='callback'){
      const st = (ev.data && ev.data.status) || (ev.data && ev.data.applied ? 'applied':'received_not_applied');
      let badge;
      if(st==='applied') badge='<span class="applied">'+I18N.BADGE_APPLIED+'</span>';
      else if(st==='observed_only') badge='<span class="observed">'+I18N.BADGE_OBSERVED+'</span>';
      else if(st==='deferred') badge='<span class="notapplied">'+I18N.BADGE_DEFERRED+'</span>';
      else badge='<span class="notapplied">'+I18N.BADGE_NOT_APPLIED+'</span>';
      ttlHtml = badge+' '+esc(ev.title);
    }
    const raw = (ev.data && Object.keys(ev.data).length)
      ? `<details class="raw"><summary>${I18N.RAW_DETAILS}</summary><pre>${esc(JSON.stringify(ev.data,null,2))}</pre></details>`:'';
    const div=document.createElement('div');
    div.className='ev';
    div.innerHTML=`<div class="when">${fmtTime(ev.ts)}</div>
      <div class="card ${side}"><div class="who">${who}</div>
      <div class="ttl">${ttlHtml}</div>
      ${ev.detail?`<div class="dtl">${esc(ev.detail)}</div>`:''}${raw}</div>`;
    tl.appendChild(div);
  });
}

async function refresh(){
  try{
    const snap = await api('/api/state');
    if($('target')!==document.activeElement && !$('target').value) $('target').value=snap.target||'';
    if($('public_url')!==document.activeElement && !$('public_url').value) $('public_url').value=snap.public_url||'';
    renderScenarios(snap);
    renderStatus(snap);
    renderEvents(snap);
  }catch(e){
    $('conn').textContent=I18N.CONN_SIM_OFFLINE;$('conn').className='pill bad';
  }
}

renderPresets();
refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>
"""


def render_ui_html(lang: str) -> str:
    """Render the embedded single-page UI for the given language.

    Uses simple ``__TOKEN__`` substitution (not str.format) so the CSS/JS
    curly braces in the template never need escaping.
    """
    lang = _lang_or_default(lang)
    strings = UI_STRINGS.get(lang, UI_STRINGS[DEFAULT_LANG])
    html = UI_HTML_TEMPLATE.replace("__HTML_LANG__", lang)
    for key, val in strings.items():
        html = html.replace(f"__{key}__", val)
    html = html.replace("__I18N_JSON__", json.dumps(strings))
    presets = PRESETS_BY_LANG.get(lang, PRESETS_BY_LANG[DEFAULT_LANG])
    html = html.replace("__PRESETS_JSON__", json.dumps(presets))
    return html


# ──────────────────────────────────────────────────────────────────────────
# Bootstrap
# ──────────────────────────────────────────────────────────────────────────


def _detect_lan_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def main() -> None:
    ap = argparse.ArgumentParser(
        description="GRD/DSO simulator for SmartGridReady-compliant EMS (e.g. casasmooth)")
    ap.add_argument("--target", default="http://192.168.68.149:28100",
                    help="EMS API base URL (default: %(default)s)")
    ap.add_argument("--token", default="",
                    help="SGr webhook token for sending/cancelling signals")
    ap.add_argument("--port", type=int, default=8770, help="UI port (default: %(default)s)")
    ap.add_argument("--public-url", default="",
                    help="Reachable URL of this simulator for EMS callbacks "
                         "(default: auto-detect LAN IP)")
    ap.add_argument("--poll-interval", type=float, default=10.0,
                    help="Seconds between EMS polls (default: %(default)s)")
    ap.add_argument("--lang", default=DEFAULT_LANG, choices=LANGS,
                    help="UI and event-log language (default: %(default)s)")
    args = ap.parse_args()

    public_url = args.public_url or f"http://{_detect_lan_ip()}:{args.port}"
    state = SimState(args.target, args.token, public_url, lang=args.lang)
    Handler.state = state
    Handler.ui_html = render_ui_html(state.lang)

    stop = threading.Event()
    poller = threading.Thread(target=poller_loop, args=(state, args.poll_interval, stop),
                              daemon=True)
    poller.start()

    auto = threading.Thread(target=auto_loop, args=(state, stop), daemon=True)
    auto.start()

    httpd = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    print("=" * 64)
    print(" SmartGridReady GRD simulator")
    print("=" * 64)
    print(f"  UI            : http://localhost:{args.port}")
    print(f"  EMS target    : {state.target}")
    print(f"  callback URL  : {state.public_url}/api/callback")
    print(f"  token         : {'set' if state.token else 'NOT set (sending disabled)'}")
    print(f"  poll interval : {args.poll_interval}s")
    print(f"  language      : {state.lang}")
    print("=" * 64)
    txt = EVT[state.lang]
    state.add_event("info", "info", txt["sim_started_title"],
                    txt["sim_started_detail"].format(
                        target=state.target, callback=f"{state.public_url}/api/callback"))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping…")
    finally:
        stop.set()
        httpd.shutdown()


if __name__ == "__main__":
    main()
