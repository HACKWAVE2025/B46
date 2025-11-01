AIHealth is an AI-driven telemedicine web platform designed to bridge the healthcare access gap between patients and certified doctors — through secure, real-time video consultations, intelligent symptom analysis, and automated health documentation.
Built during "Hack Wave 2025" at Sreenidhi Institute of Technology,  AIHealth represents the next generation of virtual healthcare — one that not only connects patients and doctors, but also understands, assists, and records every step of care.

Problem Statement:
Millions of Indians still struggle to access timely healthcare! especially in rural areas where 80% of doctors are unavailable.
Even though telemedicine platforms like eSanjeevani exist, most lack intelligent triage, multilingual communication, and persistent health history tracking.

our HealthAI aims to fix that.

Our goal:
Build a robust telemedicine platform connecting patients and certified doctors via secure, real-time video chat.
Features must include verified provider listing, AI-based symptom triage, secure e-prescriptions, and persistent health records.

Our Solution:
AIHealth I is a smart telemedicine ecosystem that empowers patients and doctors through AI and automation.

 Core Functionalities:
 
 1. Role-Based Login & Verification
Patients, Doctors, and Admins have dedicated dashboards.
Doctors upload license, certificates, and hospital ID.
Admin verifies credentials and marks verified doctors only.

 2. AI Symptom Checker
GPT-powered chatbot analyzes user-reported symptoms.
Predicts possible illnesses and prioritizes based on urgency.
Suggests relevant doctors for consultation.

3. Real-Time Video Consultation:
Secure video calling using WebRTC / Agora SDK.
Integrated live chat and bilingual subtitle support.

4. AI Voice Translator:
Enables doctor–patient communication across English, Hindi, and Telugu.
Real-time speech-to-text, translation, and text-to-speech pipeline.
Built using Whisper + Google Translate + gTTS API.

5. AI Medical Scribe:
Converts doctor–patient conversation into structured notes:
Symptoms
Diagnosis
Medications
Follow-up advice
Auto-saves summary to patient’s medical history.

6. Digital Prescription Generator:
Auto-generates digitally signed PDF prescriptions.
Includes expiry date and digital signature.
Instantly shared to patient’s WhatsApp (via Cloud API).

7. Patient Health Portfolio:
Stores all past consultations, prescriptions, and video logs.
Allows rescheduling and reminders for follow-ups.

9. Emergency Mode + Nearby Hospitals:
Uses navigator.geolocation API for real-time patient location.
Displays nearest hospitals via Google Maps API.
One-tap SOS alert to emergency contacts.
