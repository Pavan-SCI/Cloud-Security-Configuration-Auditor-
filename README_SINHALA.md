# AWS Cloud Security Configuration Auditor (සිංහල මාර්ගෝපදේශය)

මෙම ව්‍යාපෘතිය (Project) මඟින් ඔබගේ AWS (Amazon Web Services) ගිණුමේ ඇති ආරක්ෂක සැකසුම් (Security Configurations) පරීක්ෂා කර, එහි ඇති දුර්වලතා හඳුනාගෙන, ඒවා Slack මඟින් ස්වයංක්‍රීයව දැනුම් දීමට සහ Real-time වෙබ් Dashboard එකකින් බලාගැනීමට උපකාරී වේ.

---

## 1. මෙම Project එකෙන් සිදුවන්නේ කුමක්ද? (What it does)

මෙම මෙවලම (Tool) ප්‍රධාන ආරක්ෂක අංශ 2ක් ස්වයංක්‍රීයව පරීක්ෂා කරයි:
1. **IAM (Identity and Access Management) Users පරීක්ෂාව:**
   * සියලුම IAM Users ලාට **MFA (Multi-Factor Authentication)** සක්‍රිය කර තිබේදැයි පරීක්ෂා කරයි.
   * දින 90 කට වඩා පැරණි, දැනට භාවිතයේ පවතින **AWS Access Keys** තිබේදැයි සොයා බලයි.
2. **S3 Buckets පරීක්ෂාව:**
   * S3 buckets වල "Block Public Access" සක්‍රිය කර තිබේදැයි පරීක්ෂා කරයි.

---

## 2. මෙහි අඩංගු ගොනු මොනවාද? (What's in here)

* **[app.py](file:///Users/pavanwishvajayasekara/Desktop/Cloud-Security-Configuration-Auditor-/app.py)**: Flask backend server එක සහ Real-time Event streaming (SSE) හා Webhook endpoint අඩංගු ප්‍රධාන server script එකයි.
* **[main.py](file:///Users/pavanwishvajayasekara/Desktop/Cloud-Security-Configuration-Auditor-/main.py)**: AWS account එක scan කර, findings පරිගණකයේ පෙන්වා, `security_report.json` වාර්තාව සාදන ප්‍රධාන script එකයි.
* **[notifier.py](file:///Users/pavanwishvajayasekara/Desktop/Cloud-Security-Configuration-Auditor-/notifier.py)**: `security_report.json` කියවා, හඳුනාගත් ආරක්ෂක දුර්වලතා Slack channel එකකට alerts ලෙස යවන script එකයි.
* **[test_auditor.py](file:///Users/pavanwishvajayasekara/Desktop/Cloud-Security-Configuration-Auditor-/test_auditor.py)**: AWS credentials නැතිව, mock data යොදාගෙන local පරිගණකයේම code එක පරීක්ෂා කිරීමට ලියන ලද test suite එකයි.
* **[templates/index.html](file:///Users/pavanwishvajayasekara/Desktop/Cloud-Security-Configuration-Auditor-/templates/index.html)**: වගු සහ alerts සහිත dynamic dashboard frontend පිටුවයි.
* **[static/style.css](file:///Users/pavanwishvajayasekara/Desktop/Cloud-Security-Configuration-Auditor-/static/style.css)**: Glassmorphic dark-mode styling එක ලබා දෙන CSS stylesheet එකයි.

---

## 3. ක්‍රියාත්මක කරන්නේ කෙසේද? (How to Run)

### පියවර 1: AWS සමඟ පරිගණකය සම්බන්ධ කිරීම
1. **Access Keys ලබාගැනීම:** ඔබේ AWS Console -> IAM -> Security Credentials වෙත ගොස් **Access Key ID** සහ **Secret Access Key** සාදා ගන්න.
2. **Configure කිරීම:** Terminal එකෙහි පහත command එක run කර, අසන විස්තර ලබා දෙන්න:
   ```bash
   aws configure
   ```

### පියවර 2: Python Dependencies ස්ථාපනය කිරීම
```bash
python3 -m pip install boto3 flask
```

### පියවර 3: Web UI Dashboard එක Run කිරීම
```bash
python3 app.py
```
දැන් browser එකෙන් **[http://127.0.0.1:5000](http://127.0.0.1:5000)** වෙත පිවිසෙන්න.

---

## ⚡ Real-Time Event-Driven Monitoring (සැබෑ කාලීන පරීක්ෂාව)

මෙම ක්‍රමය මඟින් AWS ගිණුමේ යම් වෙනසක් (උදා: user කෙනෙක් සෑදීම හෝ bucket එකක් public කිරීම) සිදු වූ සැනින්, පිටුව refresh කිරීමකින් තොරව dashboard එකට warning එකක් සහ Slack alert එකක් ලැබෙනු ඇත.

### local පරීක්ෂා කිරීම (Mock simulation via curl)
Server එක run වෙමින් පවතින විට, වෙනත් terminal එකකින් පහත command එක run කර real-time event එකක් simulate කරන්න:
```bash
curl -X POST http://127.0.0.1:5000/api/webhook \
     -H "Content-Type: application/json" \
     -d '{"detail-type": "AWS API Call via CloudTrail", "detail": {"eventName": "CreateUser", "requestParameters": {"userName": "Insecure-Test-User"}}}'
```
*දැන් dashboard එක refresh නොවී ක්ෂණිකව warning alert එකක් පෙන්වනු ඇත.*

### සැබෑ AWS Account එකක් සමඟ සම්බන්ධ කිරීම:
1. **ngrok භාවිතයෙන් local server එක public කරන්න:**
   ```bash
   ngrok http 5000
   ```
   ලැබෙන HTTPS URL එක copy කරගන්න (e.g., `https://xxxx.ngrok-free.app/api/webhook`).
2. **AWS CloudTrail සක්‍රිය කරන්න:** AWS Console එකට ගොස් Management events සටහන් වන සේ CloudTrail එකක් සාදන්න.
3. **AWS EventBridge API Destination එකක් සාදන්න:** Destination Endpoint එකට ngrok මඟින් ලැබුණු URL එක ලබා දෙන්න.
4. **EventBridge Rule එකක් සාදන්න:** IAM සහ S3 changes (CreateUser, CreateBucket etc.) සිදුවන විට API Destination එක trigger වන සේ Rule එකක් සාදන්න.

---

## 4. Local Test Suite එක Run කිරීම (Local Testing)
කිසිදු AWS credentials එකක් නැතිව local mock data මඟින් කේතය නිවැරදිදැයි බැලීමට:
```bash
python3 -m unittest test_auditor.py
```
