#!/usr/bin/env python3
"""LEGACY — harness for the casasmooth grid-signal webhook (not SmartGridready).

This is version 1.0.0 of grd-smartgridready, kept (and repaired) for the one
job it does well: exercising casasmooth's proprietary grid-signal webhook with
a live timeline. It is NOT a SmartGridready test: SmartGridready defines the
DSO -> EMS link as functional profiles of category SGCP, reached through the
EMS's own EID with the official CommHandler — that is ``grd-sgr run``.

What 2.0.0 changed here:
  * SG-Ready states follow the BWP / SmartGridready definition (2 = NORMAL,
    3 = INTENSIFIED); 1.0.0 called 2 "reduced" and 3 "normal".
  * Security: binds 127.0.0.1 by default, every state-changing endpoint needs
    the UI token, no CORS wildcard, JSON-only bodies, and changing the target
    drops the stored webhook token (1.0.0 let any LAN host — or any web page
    via a simple POST — repoint the target and receive the Bearer token).
  * The audit is read by instant, not by string comparison of timestamps.

It is a pure HTTP client, standard library only: nothing from casasmooth is
imported and nothing is installed on the target.

It talks to the target purely over HTTP, using casasmooth's contract:

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
        --lang   en            [--expose]

Then open the URL printed at startup (it carries the UI token when
``--expose`` is used). ``--lang`` selects the UI and event-log language
(fr/en/de/it, default fr) for this run. The EMS's GET endpoints (active
signal / audit / claims) are polled without its webhook token; sending and
cancelling need it.

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
import hmac
import json
import secrets
import socket
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

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

# SG-Ready operating states as defined by the Bundesverband Wärmepumpe (BWP)
# and taken over verbatim by SmartGridready (functional profiles
# HeatPumpControl/SG-ReadyStates_bwp and SG-ReadyStates 2m):
#   1 = LOCKED (contacts 1:0, the utility lock "EVU-Sperre", hard lock <= 2 h)
#   2 = NORMAL (0:0)
#   3 = INTENSIFIED (0:1, switch-on recommendation)
#   4 = FORCED (1:1, definite switch-on command)
# Version 1.0.0 of this tool labelled 2 "reduced" and 3 "normal": a correct EMS
# then looked wrong. There is NO "reduced" SG-Ready state — reducing the load is
# a load_reduction signal (an import cap) in this legacy contract.
# These are heat-pump states (EMS -> heat pump). The DSO -> EMS link of
# SmartGridready is the SGCP category (grd-sgr run), not this webhook.
SG_READY_LABELS: dict[str, dict[int, str]] = {
    "fr": {
        1: "État 1 — Blocage EVU (verrouillage, ≤ 2 h)",
        2: "État 2 — Fonctionnement normal",
        3: "État 3 — Enclenchement recommandé (fonctionnement intensifié)",
        4: "État 4 — Ordre d'enclenchement (démarrage forcé)",
    },
    "en": {
        1: "State 1 — Utility lock (EVU-Sperre, ≤ 2 h)",
        2: "State 2 — Normal operation",
        3: "State 3 — Switch-on recommended (intensified operation)",
        4: "State 4 — Definite switch-on command (forced start)",
    },
    "de": {
        1: "Zustand 1 — EVU-Sperre (≤ 2 Std)",
        2: "Zustand 2 — Normalbetrieb",
        3: "Zustand 3 — Einschaltempfehlung (verstärkter Betrieb)",
        4: "Zustand 4 — Definitiver Einschaltbefehl (Anlaufbefehl)",
    },
    "it": {
        1: "Stato 1 — Blocco EVU (≤ 2 h)",
        2: "Stato 2 — Funzionamento normale",
        3: "Stato 3 — Accensione raccomandata (funzionamento intensificato)",
        4: "Stato 4 — Comando di accensione definitivo (avvio forzato)",
    },
}

SIGNAL_TYPE_LABELS: dict[str, dict[str, str]] = {
    "fr": {
        "sg_ready": "SG-Ready (état 1–4)",
        "load_reduction": "Délestage (plafond kW)",
        "tariff": "Tarif (CHF/kWh, non SGr)",
        "frequency": "Fréquence réseau (Hz, non SGr)",
    },
    "en": {
        "sg_ready": "SG-Ready (state 1-4)",
        "load_reduction": "Load shedding (kW cap)",
        "tariff": "Tariff (CHF/kWh, not SGr)",
        "frequency": "Grid frequency (Hz, not SGr)",
    },
    "de": {
        "sg_ready": "SG-Ready (Zustand 1-4)",
        "load_reduction": "Lastabwurf (Obergrenze kW)",
        "tariff": "Tarif (CHF/kWh, nicht SGr)",
        "frequency": "Netzfrequenz (Hz, nicht SGr)",
    },
    "it": {
        "sg_ready": "SG-Ready (stato 1-4)",
        "load_reduction": "Distacco carico (limite kW)",
        "tariff": "Tariffa (CHF/kWh, non SGr)",
        "frequency": "Frequenza di rete (Hz, non SGr)",
    },
}

# Scripted scenarios, defined ONCE (type, value, priority, reason key); only
# the texts are per language. duration_seconds is filled in by the runner from
# the step interval, so a step naturally expires once superseded.
SCENARIO_STEPS: dict[str, list[tuple]] = {
    "journee": [
        ("tariff", 0.05, 55, "night"),
        ("sg_ready", 1, 90, "morning_lock"),
        ("sg_ready", 4, 75, "noon_forced"),
        ("sg_ready", 1, 92, "evening_lock"),
        ("sg_ready", 2, 50, "evening_normal"),
    ],
    "pic_soir": [
        ("sg_ready", 2, 50, "t17_normal"),
        ("load_reduction", 5, 70, "t18_cap"),
        ("sg_ready", 1, 92, "t19_lock"),
        ("sg_ready", 2, 50, "t21_normal"),
    ],
    "surplus_pv": [
        ("sg_ready", 2, 50, "morning_normal"),
        ("sg_ready", 3, 70, "surplus_recommend"),
        ("tariff", 0.04, 60, "oversupply_price"),
        ("sg_ready", 4, 80, "peak_forced"),
        ("sg_ready", 2, 50, "evening_normal"),
    ],
    "delestage": [
        ("load_reduction", 6, 80, "cap6"),
        ("load_reduction", 3, 88, "cap3"),
        ("frequency", 49.8, 95, "underfrequency"),
        ("load_reduction", 9, 70, "cap9"),
        ("sg_ready", 2, 50, "stabilised"),
    ],
    "stress": [
        ("sg_ready", 4, 80, "stress_forced"),
        ("sg_ready", 1, 90, "stress_lock"),
        ("sg_ready", 3, 70, "stress_intensified"),
        ("sg_ready", 2, 50, "stress_normal"),
    ],
}

SCENARIO_TEXT: dict[str, dict[str, dict[str, str]]] = {
    "fr": {
        "labels": {
            "journee": "Journée type (nuit → matin → midi → soir)",
            "pic_soir": "Pic du soir (normal → plafond → blocage → normal)",
            "surplus_pv": "Journée ensoleillée (surplus PV variable)",
            "delestage": "Contrainte réseau (délestage progressif)",
            "stress": "Test de stress (états alternés rapides)",
        },
        "reasons": {
            "night": "Nuit — tarif bas, consommation encouragée",
            "morning_lock": "Pic matinal 07–09h — blocage EVU",
            "noon_forced": "Midi — surplus PV, ordre d'enclenchement",
            "evening_lock": "Pic du soir 18–20h — blocage EVU",
            "evening_normal": "Soirée — fonctionnement normal",
            "t17_normal": "17h — conditions normales",
            "t18_cap": "18h — charge réseau élevée, plafond 5 kW",
            "t19_lock": "19h — pic critique, blocage EVU",
            "t21_normal": "21h — retour au fonctionnement normal",
            "morning_normal": "Matin — production qui monte, normal",
            "surplus_recommend": "Surplus PV — enclenchement recommandé",
            "oversupply_price": "Suroffre solaire — prix très bas",
            "peak_forced": "Pic de production — ordre d'enclenchement",
            "cap6": "Contrainte réseau locale — plafond 6 kW",
            "cap3": "Aggravation — plafond 3 kW",
            "underfrequency": "Sous-fréquence réseau — réduction d'urgence",
            "cap9": "Détente — plafond 9 kW",
            "stabilised": "Réseau stabilisé — normal",
            "stress_forced": "Stress — ordre d'enclenchement",
            "stress_lock": "Stress — blocage",
            "stress_intensified": "Stress — enclenchement recommandé",
            "stress_normal": "Stress — normal",
        },
    },
    "en": {
        "labels": {
            "journee": "Typical day (night → morning → noon → evening)",
            "pic_soir": "Evening peak (normal → cap → lock → normal)",
            "surplus_pv": "Sunny day (variable PV surplus)",
            "delestage": "Grid constraint (progressive load shedding)",
            "stress": "Stress test (fast alternating states)",
        },
        "reasons": {
            "night": "Night — low tariff, consumption encouraged",
            "morning_lock": "Morning peak 07-09h — utility lock",
            "noon_forced": "Noon — PV surplus, switch-on command",
            "evening_lock": "Evening peak 18-20h — utility lock",
            "evening_normal": "Evening — normal operation",
            "t17_normal": "5pm — normal conditions",
            "t18_cap": "6pm — high grid load, 5 kW cap",
            "t19_lock": "7pm — critical peak, utility lock",
            "t21_normal": "9pm — back to normal operation",
            "morning_normal": "Morning — rising production, normal",
            "surplus_recommend": "PV surplus — switch-on recommended",
            "oversupply_price": "Solar oversupply — very low price",
            "peak_forced": "Production peak — switch-on command",
            "cap6": "Local grid constraint — 6 kW cap",
            "cap3": "Worsening — 3 kW cap",
            "underfrequency": "Grid under-frequency — emergency reduction",
            "cap9": "Easing — 9 kW cap",
            "stabilised": "Grid stabilised — normal",
            "stress_forced": "Stress — switch-on command",
            "stress_lock": "Stress — lock",
            "stress_intensified": "Stress — switch-on recommended",
            "stress_normal": "Stress — normal",
        },
    },
    "de": {
        "labels": {
            "journee": "Typischer Tag (Nacht → Morgen → Mittag → Abend)",
            "pic_soir": "Abendspitze (normal → Obergrenze → Sperre → normal)",
            "surplus_pv": "Sonniger Tag (variabler PV-Überschuss)",
            "delestage": "Netzengpass (progressiver Lastabwurf)",
            "stress": "Stresstest (schnell wechselnde Zustände)",
        },
        "reasons": {
            "night": "Nacht — niedriger Tarif, Verbrauch wird gefördert",
            "morning_lock": "Morgenspitze 07-09 Uhr — EVU-Sperre",
            "noon_forced": "Mittag — PV-Überschuss, Einschaltbefehl",
            "evening_lock": "Abendspitze 18-20 Uhr — EVU-Sperre",
            "evening_normal": "Abend — Normalbetrieb",
            "t17_normal": "17 Uhr — normale Bedingungen",
            "t18_cap": "18 Uhr — hohe Netzlast, Obergrenze 5 kW",
            "t19_lock": "19 Uhr — kritische Spitze, EVU-Sperre",
            "t21_normal": "21 Uhr — zurück zum Normalbetrieb",
            "morning_normal": "Morgen — steigende Produktion, normal",
            "surplus_recommend": "PV-Überschuss — Einschaltempfehlung",
            "oversupply_price": "Solares Überangebot — sehr niedriger Preis",
            "peak_forced": "Produktionsspitze — Einschaltbefehl",
            "cap6": "Lokaler Netzengpass — Obergrenze 6 kW",
            "cap3": "Verschärfung — Obergrenze 3 kW",
            "underfrequency": "Netzunterfrequenz — Notabsenkung",
            "cap9": "Entspannung — Obergrenze 9 kW",
            "stabilised": "Netz stabilisiert — normal",
            "stress_forced": "Stress — Einschaltbefehl",
            "stress_lock": "Stress — Sperre",
            "stress_intensified": "Stress — Einschaltempfehlung",
            "stress_normal": "Stress — normal",
        },
    },
    "it": {
        "labels": {
            "journee": "Giornata tipo (notte → mattina → mezzogiorno → sera)",
            "pic_soir": "Picco serale (normale → limite → blocco → normale)",
            "surplus_pv": "Giornata soleggiata (surplus FV variabile)",
            "delestage": "Vincolo di rete (distacco carico progressivo)",
            "stress": "Test di stress (stati alternati rapidi)",
        },
        "reasons": {
            "night": "Notte — tariffa bassa, consumo incoraggiato",
            "morning_lock": "Picco mattutino 07-09h — blocco EVU",
            "noon_forced": "Mezzogiorno — surplus FV, comando di accensione",
            "evening_lock": "Picco serale 18-20h — blocco EVU",
            "evening_normal": "Sera — funzionamento normale",
            "t17_normal": "17h — condizioni normali",
            "t18_cap": "18h — carico di rete elevato, limite 5 kW",
            "t19_lock": "19h — picco critico, blocco EVU",
            "t21_normal": "21h — ritorno al funzionamento normale",
            "morning_normal": "Mattina — produzione in aumento, normale",
            "surplus_recommend": "Surplus FV — accensione raccomandata",
            "oversupply_price": "Sovrapproduzione solare — prezzo molto basso",
            "peak_forced": "Picco di produzione — comando di accensione",
            "cap6": "Vincolo di rete locale — limite 6 kW",
            "cap3": "Aggravamento — limite 3 kW",
            "underfrequency": "Sottofrequenza di rete — riduzione d'emergenza",
            "cap9": "Allentamento — limite 9 kW",
            "stabilised": "Rete stabilizzata — normale",
            "stress_forced": "Stress — comando di accensione",
            "stress_lock": "Stress — blocco",
            "stress_intensified": "Stress — accensione raccomandata",
            "stress_normal": "Stress — normale",
        },
    },
}


def _build_scenarios(lang: str) -> dict[str, dict[str, Any]]:
    text = SCENARIO_TEXT[lang]
    return {
        key: {
            "label": text["labels"][key],
            "steps": [
                {"signal_type": t, "value": v, "priority": p, "reason": text["reasons"][r]}
                for (t, v, p, r) in steps
            ],
        }
        for key, steps in SCENARIO_STEPS.items()
    }


SCENARIOS_BY_LANG: dict[str, dict[str, dict[str, Any]]] = {lang: _build_scenarios(lang) for lang in SCENARIO_TEXT}

# Quick one-click presets shown in the sidebar: (signal, then per-language
# title / description / reason).
PRESET_SIGNALS: list[dict[str, Any]] = [
    {"signal_type": "sg_ready", "value": 4, "priority": 75, "duration_seconds": 3600},
    {"signal_type": "sg_ready", "value": 1, "priority": 90, "duration_seconds": 1800},
    {"signal_type": "sg_ready", "value": 3, "priority": 60, "duration_seconds": 3600},
    {"signal_type": "sg_ready", "value": 2, "priority": 50, "duration_seconds": 3600},
    {"signal_type": "load_reduction", "value": 3, "priority": 85, "duration_seconds": 1800},
    {"signal_type": "tariff", "value": 0.05, "priority": 55, "duration_seconds": 3600},
    {"signal_type": "tariff", "value": 0.42, "priority": 70, "duration_seconds": 3600},
    {"signal_type": "frequency", "value": 49.8, "priority": 95, "duration_seconds": 900},
]

PRESET_TEXT: dict[str, list[tuple]] = {
    "fr": [
        ("Surplus PV / suroffre", "SG-Ready état 4 — ordre d'enclenchement", "Suroffre solaire — absorber le surplus"),
        ("Pic de demande", "SG-Ready état 1 — blocage EVU", "Pic de demande réseau — blocage"),
        ("Enclenchement recommandé", "SG-Ready état 3 — fonctionnement intensifié", "Énergie abondante — enclenchement recommandé"),
        ("Normal", "SG-Ready état 2 — fonctionnement normal", "Conditions normales"),
        ("Délestage 3 kW", "load_reduction — plafond d'import", "Contrainte réseau locale 3 kW"),
        ("Tarif bas 0.05", "tariff — incite la consommation (non SGr)", "Fenêtre tarifaire basse"),
        ("Tarif haut 0.42", "tariff — incite l'effacement (non SGr)", "Fenêtre tarifaire haute"),
        ("Sous-fréquence", "frequency 49.8 Hz — réduire (non SGr)", "Sous-fréquence réseau"),
    ],
    "en": [
        ("PV surplus / oversupply", "SG-Ready state 4 — switch-on command", "Solar oversupply — absorb the surplus"),
        ("Demand peak", "SG-Ready state 1 — utility lock", "Grid demand peak — lock"),
        ("Switch-on recommended", "SG-Ready state 3 — intensified operation", "Abundant energy — switch-on recommended"),
        ("Normal", "SG-Ready state 2 — normal operation", "Normal conditions"),
        ("Load shedding 3 kW", "load_reduction — import cap", "Local grid constraint 3 kW"),
        ("Low tariff 0.05", "tariff — encourages consumption (not SGr)", "Low-tariff window"),
        ("High tariff 0.42", "tariff — encourages load shifting (not SGr)", "High-tariff window"),
        ("Under-frequency", "frequency 49.8 Hz — reduce (not SGr)", "Grid under-frequency"),
    ],
    "de": [
        ("PV-Überschuss / Überangebot", "SG-Ready Zustand 4 — Einschaltbefehl", "Solares Überangebot — Überschuss aufnehmen"),
        ("Nachfragespitze", "SG-Ready Zustand 1 — EVU-Sperre", "Netznachfragespitze — Sperre"),
        ("Einschaltempfehlung", "SG-Ready Zustand 3 — verstärkter Betrieb", "Reichlich Energie — Einschaltempfehlung"),
        ("Normal", "SG-Ready Zustand 2 — Normalbetrieb", "Normale Bedingungen"),
        ("Lastabwurf 3 kW", "load_reduction — Bezugsobergrenze", "Lokaler Netzengpass 3 kW"),
        ("Niedriger Tarif 0.05", "tariff — fördert Verbrauch (nicht SGr)", "Niedertarif-Fenster"),
        ("Hoher Tarif 0.42", "tariff — fördert Lastverschiebung (nicht SGr)", "Hochtarif-Fenster"),
        ("Unterfrequenz", "frequency 49.8 Hz — reduzieren (nicht SGr)", "Netzunterfrequenz"),
    ],
    "it": [
        ("Surplus FV / sovrapproduzione", "SG-Ready stato 4 — comando di accensione", "Sovrapproduzione solare — assorbire il surplus"),
        ("Picco di domanda", "SG-Ready stato 1 — blocco EVU", "Picco di domanda di rete — blocco"),
        ("Accensione raccomandata", "SG-Ready stato 3 — funzionamento intensificato", "Energia abbondante — accensione raccomandata"),
        ("Normale", "SG-Ready stato 2 — funzionamento normale", "Condizioni normali"),
        ("Distacco carico 3 kW", "load_reduction — limite di prelievo", "Vincolo di rete locale 3 kW"),
        ("Tariffa bassa 0.05", "tariff — incentiva il consumo (non SGr)", "Finestra tariffaria bassa"),
        ("Tariffa alta 0.42", "tariff — incentiva il rinvio dei carichi (non SGr)", "Finestra tariffaria alta"),
        ("Sottofrequenza", "frequency 49.8 Hz — ridurre (non SGr)", "Sottofrequenza di rete"),
    ],
}

PRESETS_BY_LANG: dict[str, list[dict[str, Any]]] = {
    lang: [
        {"t": t, "d": d, "sig": {**sig, "reason": reason}}
        for sig, (t, d, reason) in zip(PRESET_SIGNALS, texts, strict=True)
    ]
    for lang, texts in PRESET_TEXT.items()
}

# Server-generated event-log message templates (Python str.format placeholders).
EVT: dict[str, dict[str, str]] = {
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
UI_STRINGS: dict[str, dict[str, str]] = {
    "fr": {
        "DOC_TITLE": "Simulateur GRD · SmartGridReady",
        "BRAND_SUFFIX": "Simulateur GRD",
        "BRAND_SUB": "Banc du webhook casasmooth (historique, pas la communication SmartGridready — voir grd-sgr run)",
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
        "BRAND_SUB": "casasmooth webhook harness (legacy, not SmartGridready communication — see grd-sgr run)",
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
        "BRAND_SUB": "Prüfstand für den casasmooth-Webhook (Legacy, keine SmartGridready-Kommunikation — siehe grd-sgr run)",
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
        "BRAND_SUB": "Banco del webhook casasmooth (legacy, non comunicazione SmartGridready — vedi grd-sgr run)",
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


def _lang_or_default(lang: str | None) -> str:
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
        self.events: list[dict[str, Any]] = []
        self.sent_signals: dict[str, dict[str, Any]] = {}
        self.last_audit_ts: str | None = None
        self.auto: dict[str, Any] = {
            "running": False,
            "scenario": None,
            "interval": 60,
            "loop": True,
            "index": 0,
            "next_at": 0.0,
        }
        self.last_poll: dict[str, Any] = {
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
                  detail: str = "", data: dict[str, Any] | None = None) -> dict[str, Any]:
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

    def snapshot(self) -> dict[str, Any]:
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

    def set_config(self, target: str | None, token: str | None,
                   public_url: str | None) -> None:
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
                    # The webhook token belongs to the EMS it was given for:
                    # never send it to a new target unless it comes again with
                    # the change (1.0.0 kept it, so repointing the target
                    # exfiltrated it at the next send).
                    if token is None:
                        self.token = ""
            if token is not None:
                self.token = token
            if public_url is not None:
                self.public_url = public_url.rstrip("/")

    # -- automatic scenario player ----------------------------------------

    def start_auto(self, scenario: str, interval: float, loop: bool) -> dict[str, Any]:
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

    def stop_auto(self) -> dict[str, Any]:
        with self.lock:
            was = self.auto["running"]
            self.auto["running"] = False
        if was:
            self.add_event("info", "info", EVT[self.lang]["auto_stopped"], "")
        return {"ok": True}


# ──────────────────────────────────────────────────────────────────────────
# EMS API client (stdlib only)
# ──────────────────────────────────────────────────────────────────────────


def _http_json(method: str, url: str, token: str | None = None,
               body: dict[str, Any] | None = None, timeout: float = 8.0):
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
    except (TimeoutError, urllib.error.URLError, OSError) as exc:
        return 0, str(getattr(exc, "reason", exc))


# ──────────────────────────────────────────────────────────────────────────
# Signal sending / cancelling
# ──────────────────────────────────────────────────────────────────────────


def humanise_signal(sig: dict[str, Any], lang: str) -> str:
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


def send_signal(state: SimState, payload: dict[str, Any]) -> dict[str, Any]:
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


def cancel_signals(state: SimState, signal_id: str | None = None) -> dict[str, Any]:
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


def _instant(raw: Any) -> datetime | None:
    """ISO-8601 timestamp -> aware datetime (UTC if naive); None if unreadable."""
    if not raw or not isinstance(raw, str):
        return None
    text = raw.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        value = datetime.fromisoformat(text)
    except ValueError:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def poll_ems(state: SimState) -> None:
    """Fetch active signals, audit log and claims; stream new reactions."""
    target = state.snapshot()["target"]
    txt = EVT.get(state.lang, EVT[DEFAULT_LANG])

    s1, active = _http_json("GET", f"{target}/api/sgr/grid-signal")
    # 50, not 8: between two polls an EMS can write more cycle entries than a
    # small page holds, and a missed entry is a missed reaction.
    s2, audit = _http_json("GET", f"{target}/api/sgr/audit?limit=50")
    s3, claims = _http_json("GET", f"{target}/api/sgr/claims")

    ok = s1 == 200
    error = None if ok else (active if isinstance(active, str) else json.dumps(active))

    active_list = active.get("all_signals", []) if isinstance(active, dict) else []
    audit_entries = audit.get("entries", []) if isinstance(audit, dict) else []
    claim_list = claims.get("claims", []) if isinstance(claims, dict) else []

    # Detect newly-added audit entries (newest first from the API) and surface
    # the ones that reacted to a grid signal as EMS reactions.
    new_entries: list[dict[str, Any]] = []
    with state.lock:
        last_ts = state.last_audit_ts
    last_instant = _instant(last_ts) if last_ts else None
    for entry in reversed(audit_entries):  # oldest → newest
        instant = _instant(entry.get("timestamp"))
        if instant is None:
            continue
        # Compared as INSTANTS: "...Z" and "...+00:00" of the same second, or a
        # local offset, do not sort the same way as strings.
        if last_instant is None or instant > last_instant:
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
        stamps = [e.get("timestamp") for e in audit_entries if _instant(e.get("timestamp"))]
        newest_ts = max(stamps, key=_instant) if stamps else None
        with state.lock:
            current = _instant(state.last_audit_ts) if state.last_audit_ts else None
            if newest_ts and (current is None or _instant(newest_ts) > current):
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


def _slim_ctx(ctx: dict[str, Any]) -> dict[str, Any]:
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
    ui_token: str = ""      # injected; "" disables the check (--no-auth, loopback only)
    protect_ui: bool = False  # True when bound to a non-loopback address
    # Host names this harness answers to. A DNS-rebinding page reaches
    # 127.0.0.1 under ITS OWN name: refusing any other Host keeps it from
    # reading the page (which embeds the UI token) and from posting as
    # same-origin. Empty = no check (tests building the handler directly).
    allowed_hosts: frozenset = frozenset()
    server_version = "GRDSim/2.0"

    # Endpoints that make the EMS (and therefore a building) act, or that
    # repoint the simulator. /api/callback is NOT here: the EMS posts its ACK
    # there and does not know the simulator's token.
    PROTECTED = ("/api/send", "/api/cancel", "/api/config", "/api/auto/start",
                 "/api/auto/stop", "/api/poll-now")

    def log_message(self, fmt, *args):  # quieter logs
        pass

    # -- helpers -----------------------------------------------------------

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # No Access-Control-Allow-Origin: the UI is served from this very
        # origin. 1.0.0 sent "*", and with no token any web page the operator
        # had open could POST /api/send and make a building act.
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _host_ok(self) -> bool:
        if not self.allowed_hosts:
            return True
        host = (self.headers.get("Host") or "").strip().lower()
        if host.startswith("["):  # [::1]:8770
            name = host.split("]", 1)[0] + "]"
        else:
            name = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
        return name in self.allowed_hosts

    def _refuse_host(self) -> bool:
        if self._host_ok():
            return False
        self._json(421, {"ok": False, "error": "unexpected Host header"})
        return True

    def _authorized(self) -> bool:
        """``X-Sim-Token`` header (what the UI sends) or ``?token=`` (to open
        the UI of an exposed bind in a browser). Constant-time comparison."""
        if not self.ui_token:
            return True
        supplied = self.headers.get("X-Sim-Token") or self._query().get("token", "")
        return hmac.compare_digest(str(supplied), self.ui_token)

    def _deny(self) -> None:
        self._json(401, {"ok": False, "error": "missing or invalid simulator token "
                                               "(X-Sim-Token header or ?token=)"})

    def _json_content(self) -> bool:
        """State-changing requests must be application/json: a form or
        text/plain POST is exactly what a foreign web page can send without a
        CORS preflight."""
        return (self.headers.get("Content-Type") or "").split(";")[0].strip() == "application/json"

    def _json(self, code: int, obj: Any) -> None:
        self._send(code, json.dumps(obj).encode("utf-8"), "application/json")

    def _read_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", 0) or 0)
        if not length:
            return {}
        raw = self.rfile.read(length).decode("utf-8", "replace")
        try:
            return json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return {}

    def _query(self) -> dict[str, str]:
        if "?" not in self.path:
            return {}
        from urllib.parse import parse_qs, urlparse
        q = urlparse(self.path).query
        return {k: v[0] for k, v in parse_qs(q).items()}

    # -- routing -----------------------------------------------------------

    def do_GET(self):
        if self._refuse_host():
            return
        path = self.path.split("?", 1)[0]
        if path == "/" or path == "/index.html":
            if self.protect_ui and not self._authorized():
                self._deny()
                return
            page = self.ui_html.replace("__SIM_UI_TOKEN__", self.ui_token)
            self._send(200, page.encode("utf-8"), "text/html; charset=utf-8")
        elif path == "/api/state":
            if self.protect_ui and not self._authorized():
                self._deny()
                return
            self._json(200, self.state.snapshot())
        elif path == "/api/poll-now":
            if not self._authorized():
                self._deny()
                return
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
        if self._refuse_host():
            return
        path = self.path.split("?", 1)[0]
        if path in self.PROTECTED:
            if not self._authorized():
                self._deny()
                return
            if not self._json_content():
                self._json(415, {"ok": False, "error": "Content-Type must be application/json"})
                return
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
        if self._refuse_host():
            return
        if self.path.split("?", 1)[0] == "/api/cancel":
            if not self._authorized():
                self._deny()
                return
            self._json(200, cancel_signals(self.state, self._query().get("signal_id")))
        else:
            self._json(404, {"error": "not found"})

    # -- callback handling -------------------------------------------------

    def _handle_callback(self, corr: str | None, body: dict[str, Any]) -> None:
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
const UI_TOKEN = "__SIM_UI_TOKEN__";

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
  opts = opts || {};
  opts.headers = Object.assign({}, opts.headers || {}, UI_TOKEN ? {'X-Sim-Token': UI_TOKEN} : {});
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


def allowed_host_names(public_url: str, exposed: bool) -> frozenset:
    """Loopback names always; when exposed, this machine's names and the host
    of the public (callback) URL — what a legitimate client can call it."""
    from urllib.parse import urlparse

    names = {"localhost", "127.0.0.1", "[::1]"}
    if exposed:
        names |= {_detect_lan_ip(), socket.gethostname().lower(), socket.getfqdn().lower()}
        host = urlparse(public_url).hostname
        if host:
            names.add(host.lower())
    return frozenset(n for n in names if n)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="LEGACY harness for the casasmooth grid-signal webhook (not SmartGridready "
                    "communication — for that, use `grd-sgr run`)")
    ap.add_argument("--target", default="http://127.0.0.1:28100",
                    help="EMS API base URL (default: %(default)s)")
    ap.add_argument("--token", default="",
                    help="EMS webhook token for sending/cancelling signals")
    ap.add_argument("--port", type=int, default=8770, help="UI port (default: %(default)s)")
    ap.add_argument("--public-url", default="",
                    help="Reachable URL of this simulator for EMS callbacks "
                         "(default: auto-detect LAN IP)")
    ap.add_argument("--poll-interval", type=float, default=10.0,
                    help="Seconds between EMS polls (default: %(default)s)")
    ap.add_argument("--lang", default=DEFAULT_LANG, choices=LANGS,
                    help="UI and event-log language (default: %(default)s)")
    ap.add_argument("--expose", action="store_true",
                    help="listen on all interfaces instead of 127.0.0.1 (needed when the EMS "
                         "must reach the callback URL); the UI token then protects the page too")
    ap.add_argument("--ui-token", default="",
                    help="token protecting this simulator's own endpoints (default: generated)")
    ap.add_argument("--no-auth", action="store_true",
                    help="disable the simulator token (loopback debugging only; refused with --expose)")
    args = ap.parse_args()

    bind_host = "0.0.0.0" if args.expose else "127.0.0.1"  # noqa: S104 - explicit opt-in
    ui_token = "" if args.no_auth else (args.ui_token or secrets.token_urlsafe(18))
    if args.expose and not ui_token:
        raise SystemExit("--expose with --no-auth would let anyone on the LAN send grid "
                         "signals to a building; refusing to start.")
    public_url = args.public_url or f"http://{_detect_lan_ip()}:{args.port}"
    state = SimState(args.target, args.token, public_url, lang=args.lang)
    Handler.state = state
    Handler.ui_html = render_ui_html(state.lang)
    Handler.ui_token = ui_token
    Handler.protect_ui = args.expose
    Handler.allowed_hosts = allowed_host_names(public_url, args.expose)

    stop = threading.Event()
    poller = threading.Thread(target=poller_loop, args=(state, args.poll_interval, stop),
                              daemon=True)
    poller.start()

    auto = threading.Thread(target=auto_loop, args=(state, stop), daemon=True)
    auto.start()

    httpd = ThreadingHTTPServer((bind_host, args.port), Handler)
    ui_url = f"http://{'localhost' if not args.expose else _detect_lan_ip()}:{args.port}/"
    if ui_token and args.expose:
        ui_url += f"?token={ui_token}"
    print("=" * 64)
    print(" casasmooth webhook harness (legacy — not SmartGridready communication)")
    print("=" * 64)
    print(f"  UI            : {ui_url}")
    print(f"  listening on  : {bind_host}" + ("  (LAN: the UI token is required)" if args.expose
                                            else "  (this machine only)"))
    print(f"  UI token      : {'disabled (--no-auth)' if not ui_token else ui_token}")
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
