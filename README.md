🛡️ PHISH-XAI: Phishing URL Detection with Explainable AI
PHISH-XAI is an advanced phishing detection system built using Python, Machine Learning, and Explainable AI techniques. It helps users identify phishing URLs by extracting important URL-based features, performing classification using an ensemble of ML models, and providing explainability through triggered keyword alerts and risk profiling.

🚀 Features
🔍 Phishing URL Detection using an Ensemble ML classifier (Random Forest, Logistic Regression, SVM)

📋 Real-time Feature Extraction including domain age, IP presence, HTTPS, suspicious keywords, and more

🧠 Explainable AI: Shows which keywords triggered the prediction and URL metadata

📊 Dashboard: Visualize Safe vs Phishing URL stats and model accuracy

📝 History: Keep track of previously tested URLs

📦 Tkinter GUI with tabbed navigation (Home, Detector, Stats, About)

🧠 Machine Learning Workflow
Dataset: Accepts a CSV file (phishing_data.csv) with url and label columns

Feature Engineering:

URL Length

IP address presence

Number of dots and dashes

HTTPS usage

@ symbol usage

Suspicious keyword count

Domain age (via WHOIS lookup)

Models Used:

Random Forest

Logistic Regression

Support Vector Machine (SVM)

Voting Strategy:

Ensemble classifier with majority voting

Average probability for final confidence score

📂 Folder Structure
bash
Copy
Edit
📁 PHISH-XAI
├── phishing_data.csv        # Input dataset
├── phish_xai.py             # Main Python script (GUI + ML pipeline)
├── README.md                # This README file
🛠️ How to Run
Install dependencies:

bash
Copy
Edit
pip install pandas numpy scikit-learn matplotlib tk python-whois
Prepare the dataset:

Make sure you have a CSV file named phishing_data.csv with two columns:

url: the website URL

label: either phishing or safe

Run the app:

bash
Copy
Edit
python phish_xai.py


📊 Accuracy
The trained ensemble model achieves an accuracy of ~{accuracy:.2f}% on the test set.

⚠️ Suspicious Keywords Used
The app scans for the following phishing-related terms in URLs:

pgsql
Copy
Edit
login, verify, update, secure, bank, account, confirm, admin, password, payment,
recovery, access, authentication, billing, security, user, profile, signin,
signup, reset, unlock, validate, authorize, transaction, card, credit, debit
🔐 Explainability Output Example
yaml
Copy
Edit
Result: NOT SAFE (91.25%)
⚠ Triggered Keywords: login, bank, password
Length: 66, IP: 0, HTTPS: 1, @: 0, Domain Age: 43 days
🧑‍💻 Developed By
Mohd Farhaz
B.Tech Student, Jamia Hamdard University
GitHub: @mohdfarhazz

📘 License
This project is for academic and educational purposes only. Use responsibly.
Feel free to fork and improve — please provide credit when doing so.
