# 🔐 Phishing Detector Chrome Extension

A smart Chrome extension that detects phishing websites using URL and page analysis.

---

## 🚀 Features
- Real-time phishing detection
- Risk score calculation
- Risk level (Safe / Suspicious / High Risk)
- Reasons for detection
- Warning page for dangerous sites
- Scan history tracking

---

## 🧠 How it Works
The extension checks:
- HTTPS or not
- Suspicious symbols (@)
- Password fields
- URL length
- Keywords (login, verify, bank, update)
- IP address in URL
- Too many dots in domain
- Form redirect to another domain
- Hidden iframes
- External scripts
- Suspicious page text

Then it generates a **Risk Score**.

---

## 📁 Project Structure

phishing-detector-extension/
├── manifest.json
├── service-worker.js
├── content.js
├── popup.html
├── popup.js
├── popup.css
├── warning.html
├── warning.js
├── history.html
├── history.js


---

## 🛠️ Installation (Manual)
1. Download ZIP
2. Extract it
3. Open Chrome → `chrome://extensions`
4. Enable Developer Mode
5. Click **Load unpacked**
6. Select the folder

---

## 🧪 Testing
- Open any website
- Click extension icon
- View Risk Score and Reasons
- Try test phishing page

---

## 📌 Future Improvements
- Backend integration
- Machine learning model
- Real-time blacklist API
- Better UI/UX

---

## 👨‍💻 Author
Aayush Prasad