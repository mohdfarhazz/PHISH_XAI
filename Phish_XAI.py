import pandas as pd
import re
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import LabelEncoder, StandardScaler
import numpy as np
import tkinter as tk
from tkinter import ttk, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from datetime import datetime
import concurrent.futures
import whois

# Suspicious keywords
suspicious_keywords = ['login', 'verify', 'update', 'secure', 'bank', 'account','confirm', 'admin', 'password', 'payment',
                        'recovery', 'access', 'authentication', 'billing', 'security', 'user', 'profile', 'signin',
                        'signup', 'reset', 'unlock', 'validate', 'authorize', 'transaction', 'card', 'credit', 'debit']

# WHOIS with timeout using concurrent futures
def safe_whois_lookup(domain, timeout=3):
    def _lookup():
        return whois.whois(domain)

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future = executor.submit(_lookup)
        try:
            return future.result(timeout=timeout)
        except Exception:
            return None

# Full feature extractor with WHOIS
def extract_features_with_whois(url):
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split('/')[0]
    domain_age = -1

    try:
        w = safe_whois_lookup(domain)
        if w:
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date and isinstance(creation_date, datetime):
                domain_age = (datetime.now() - creation_date).days
    except:
        pass

    features = {
        'url_length': len(url),
        'has_ip': 1 if re.search(r'\d+\.\d+\.\d+\.\d+', parsed.netloc) else 0,
        'count_dot': url.count('.'),
        'count_dash': url.count('-'),
        'https': 1 if parsed.scheme == 'https' else 0,
        'has_at': 1 if '@' in url else 0,
        'suspicious_keywords_count': sum(1 for kw in suspicious_keywords if kw in url.lower()),
        'trigger_keywords': ', '.join([kw for kw in suspicious_keywords if kw in url.lower()]) or 'None',
        'domain_age': domain_age
    }
    return features

# Fast feature extractor without WHOIS (for training only)
def extract_features_no_whois(url):
    parsed = urlparse(url)
    features = {
        'url_length': len(url),
        'has_ip': 1 if re.search(r'\d+\.\d+\.\d+\.\d+', parsed.netloc) else 0,
        'count_dot': url.count('.'),
        'count_dash': url.count('-'),
        'https': 1 if parsed.scheme == 'https' else 0,
        'has_at': 1 if '@' in url else 0,
        'suspicious_keywords_count': sum(1 for kw in suspicious_keywords if kw in url.lower()),
        'trigger_keywords': ', '.join([kw for kw in suspicious_keywords if kw in url.lower()]) or 'None',
        'domain_age': -1  # Skipped for speed
    }
    return features

# Custom Ensemble Classifier
class EnsembleClassifier:
    def __init__(self):
        self.models = [
            ('RandomForest', RandomForestClassifier(n_estimators=100, random_state=42)),
            ('LogisticRegression', LogisticRegression(max_iter=1000, random_state=42)),
            ('SVM', SVC(probability=True, random_state=42))
        ]
        self.scaler = StandardScaler()

    def fit(self, X, y):
        # Standardize features for Logistic Regression and SVM
        X_scaled = self.scaler.fit_transform(X)
        for name, model in self.models:
            if name in ['LogisticRegression', 'SVM']:
                model.fit(X_scaled, y)
            else:
                model.fit(X, y)

    def predict_proba(self, X):
        X_scaled = self.scaler.transform(X)
        probas = []
        for name, model in self.models:
            if name in ['LogisticRegression', 'SVM']:
                probas.append(model.predict_proba(X_scaled))
            else:
                probas.append(model.predict_proba(X))
        # Average probabilities across models
        return np.mean(probas, axis=0)

    def predict(self, X):
        X_scaled = self.scaler.transform(X)
        predictions = []
        for name, model in self.models:
            if name in ['LogisticRegression', 'SVM']:
                predictions.append(model.predict(X_scaled))
            else:
                predictions.append(model.predict(X))
        # Majority voting
        predictions = np.array(predictions)
        return np.apply_along_axis(lambda x: np.bincount(x).argmax(), axis=0, arr=predictions)

# Load dataset and train model
try:
    df = pd.read_csv("phishing_data.csv")
except FileNotFoundError:
    print("❌ Error: phishing_data.csv not found!")
    exit()

df['features'] = df['url'].apply(extract_features_no_whois)
feature_df = pd.json_normalize(df['features'])
df = pd.concat([df, feature_df], axis=1)

label_encoder = LabelEncoder()
df['label_encoded'] = label_encoder.fit_transform(df['label'])

X = df[['url_length', 'has_ip', 'count_dot', 'count_dash', 'https',
        'has_at', 'suspicious_keywords_count', 'domain_age']]
y = df['label_encoded']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train ensemble model
ensemble = EnsembleClassifier()
ensemble.fit(X_train, y_train)
y_pred = ensemble.predict(X_test)
accuracy = accuracy_score(y_test, y_pred) * 100

# Tkinter App
class PhishXAIApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PHISH-XAI: Phishing URL Detector")
        self.geometry("850x600")
        self.configure(bg="#f8f9fa")

        self.history = []

        self.create_tabs()

    def create_tabs(self):
        tab_control = ttk.Notebook(self)

        self.home_tab = ttk.Frame(tab_control)
        self.predict_tab = ttk.Frame(tab_control)
        self.stats_tab = ttk.Frame(tab_control)
        self.about_tab = ttk.Frame(tab_control)

        tab_control.add(self.home_tab, text='🏠 Home')
        tab_control.add(self.predict_tab, text='🛡️ Detector')
        tab_control.add(self.stats_tab, text='📊 Stats')
        tab_control.add(self.about_tab, text='ℹ️ About')
        tab_control.pack(expand=1, fill='both')

        self.setup_home()
        self.setup_predict()
        self.setup_stats()
        self.setup_about()

    def setup_home(self):
        tk.Label(self.home_tab, text="Welcome to PHISH-XAI", font=("Helvetica", 24, "bold")).pack(pady=20)
        tk.Label(self.home_tab, text="Created by Mohd Farhaz", font=("Helvetica", 20)).pack(pady=5)
        tk.Label(self.home_tab, text="Jamia Hamdard University", font=("Helvetica", 18)).pack(pady=5)
        tk.Label(self.home_tab, text="\nThis tool detects phishing URLs using Machine Learning.", font=("Helvetica", 17)).pack(pady=20)

    def setup_predict(self):
        frame = ttk.Frame(self.predict_tab)
        frame.pack(pady=20)

        tk.Label(frame, text="🔗 Enter URL:", font=("Helvetica", 12)).grid(row=0, column=0, sticky='w')
        self.url_entry = tk.Entry(frame, width=80)
        self.url_entry.grid(row=0, column=1)

        self.result_label = tk.Label(self.predict_tab, text="", font=("Helvetica", 14, "bold"))
        self.result_label.pack(pady=10)

        self.keywords_label = tk.Label(self.predict_tab, text="", font=("Helvetica", 11))
        self.keywords_label.pack()

        self.details_label = tk.Label(self.predict_tab, text="", font=("Helvetica", 10))
        self.details_label.pack()

        button_frame = ttk.Frame(self.predict_tab)
        button_frame.pack(pady=10)

        ttk.Button(button_frame, text="Predict", command=self.predict_url).grid(row=0, column=0, padx=5)
        ttk.Button(button_frame, text="Copy Result", command=self.copy_result).grid(row=0, column=1, padx=5)

        tk.Label(self.predict_tab, text="\nHistory:", font=("Helvetica", 10)).pack()
        self.history_var = tk.StringVar()
        self.history_dropdown = ttk.Combobox(self.predict_tab, textvariable=self.history_var, width=80)
        self.history_dropdown.pack()
        self.history_dropdown.bind("<<ComboboxSelected>>", self.use_history)

    def setup_stats(self):
        fig, ax = plt.subplots(figsize=(4, 4))
        labels = ['Safe', 'Phishing']
        sizes = [sum(y == 0), sum(y == 1)]
        colors = ['#2ecc71', '#e74c3c']
        ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=colors)
        ax.axis('equal')

        canvas = FigureCanvasTkAgg(fig, master=self.stats_tab)
        canvas.draw()
        canvas.get_tk_widget().pack()

        tk.Label(self.stats_tab, text=f"Ensemble Model Accuracy: {accuracy:.2f}%", font=("Helvetica", 12)).pack(pady=10)

    def setup_about(self):
        tk.Label(self.about_tab, text="About This Project", font=("Helvetica", 16, "bold")).pack(pady=20)
        tk.Label(self.about_tab, text="PHISH-XAI is a phishing detection system built using Python,\nMachine Learning, and Explainable AI techniques.", font=("Helvetica", 12)).pack(pady=5)
        tk.Label(self.about_tab, text="Developed by Mohd Farhaz\nB.Tech Student, Jamia Hamdard University", font=("Helvetica", 11)).pack(pady=10)
        tk.Label(self.about_tab, text="For academic and educational use only.", font=("Helvetica", 10, "italic"), fg="gray").pack(pady=5)

    def predict_url(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a URL.")
            return

        features = extract_features_with_whois(url)
        input_df = pd.DataFrame([features])[X.columns]
        score = ensemble.predict_proba(input_df)[0][1]
        label = "SAFE" if score >= 0.5 else "NOT SAFE"
        confidence = f"{score * 100:.2f}%"

        self.result_label.config(text=f"Result: {label} ({confidence})", fg="#2ecc71" if label == "SAFE" else "#e74c3c")
        self.keywords_label.config(text=f"⚠ Triggered Keywords: {features['trigger_keywords']}")
        self.details_label.config(text=(
            f"Length: {features['url_length']}, IP: {features['has_ip']}, HTTPS: {features['https']}, "
            f"@: {features['has_at']}, Domain Age: {features['domain_age']} days"
        ))

        self.history.append(url)
        self.history_dropdown['values'] = self.history

    def use_history(self, event):
        selected = self.history_var.get()
        self.url_entry.delete(0, tk.END)
        self.url_entry.insert(0, selected)

    def copy_result(self):
        report = f"{self.result_label['text']}\n{self.keywords_label['text']}\n{self.details_label['text']}"
        self.clipboard_clear()
        self.clipboard_append(report)
        messagebox.showinfo("Copied", "Result copied to clipboard!")

# --- Run App ---
if __name__ == '__main__':
    try:
        app = PhishXAIApp()
        app.mainloop()
    except Exception as e:
        print("❌ GUI Error:", e)