# ⚠️ **Threat Hunt Report: Bryce Montgomery Investigation** ⚡️

---

## 📈 **Platforms and Languages Leveraged**
### 🛠️ **Platforms:**
- 📂 Microsoft Sentinel (**Log Analytics Workspace**)
- 💻 Windows-based corporate workstations (**corporate & shared environments**)
- 🛏️ Shared guest workstations (**campus-based**)

### 🛠️ **Languages/Tools:**
- 📄 **Kusto Query Language (KQL)** - Querying device events, process logs & file activities.
- 🔒 **Steganography tools** - *Steghide.exe* (embedding data into images).
- 📁 **7z.exe** - Compressing & packaging files for potential exfiltration.

---

## 🔒 **Scenario**
The **VP of Risk** requested an investigation due to suspicions that **Bryce Montgomery** (🔑 *username: bmontgomery*), a company executive, had engaged in **unauthorized access & exfiltration of corporate intellectual property**. The investigation focused on Bryce's **corporate workstation** (*corp-ny-it-0334*) and possible **misuse of shared workstations**.

### **Key Concerns**:
- **User:** Bryce Montgomery (**bmontgomery**)
- **Primary Workstation:** *corp-ny-it-0334*, but **guest workstations were also suspected**
- **Threat:** **Data exfiltration** using steganography & file compression
- **Risk:** Executives had **full administrative privileges** & were **exempt from Data Loss Prevention (DLP) policies**, making detection harder.

---

## 🛡️ **Steps Taken**

### 1. 🔍 **Investigating Bryce Montgomery's Workstation**
- **KQL Query** executed on `corp-ny-it-0334` to track file interactions.
- Identified file **"Q1-2025-ResearchAndDevelopment.pdf"** & its **hash** (`b3302e58be7eb604fda65d1d04a5e18325c66792`).

**Query Used:**
```kql
DeviceFileEvents
| where DeviceName == "corp-ny-it-0334"
| where InitiatingProcessAccountName == "bmontgomery"
| project FileName, FolderPath, SHA256, SHA1, MD5
```

---

### 2. 🌍 **Cross-Reference on Shared Workstations**
- Checked guest workstations **Bryce may have used**.
- Found **"lobby-fl2-ae5fc"** had matching files, indicating access under a **guest profile**.
- Data **obfuscation tactics** used to rename sensitive files.

**Query Used:**

------

```kql
DeviceFileEvents
| where SHA256 == "ec727a15bf51e027b9a1bbf097cfa9d57e46aa159bfa37f68dca5e3c5df5af3d"
| union DeviceProcessEvents
| where SHA256 == "ec727a15bf51e027b9a1bbf097cfa9d57e46aa159bfa37f68dca5e3c5df5af3d"
| union DeviceEvents
| where SHA256 == "ec727a15bf51e027b9a1bbf097cfa9d57e46aa159bfa37f68dca5e3c5df5af3d"
| order by Timestamp asc
```
---

### 3. 🔒 **Steganography Detection**
- **Steghide.exe** was used to embed files into images.
- **Images involved:** `suzie-and-bob.bmp`, `bryce-and-kid.bmp`, `bryce-fishing.bmp`.
- Hidden documents found in **C:\\ProgramData\\**.

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "lobby-fl2-ae5fc"
| where ProcessCommandLine contains "bryce-homework-fall-2024.pdf" or ProcessCommandLine contains "Amazon-Order-123456789-Invoice.pdf" or ProcessCommandLine contains "temp___2bbf98cf.pdf"
| order by Timestamp desc
| project Timestamp ,DeviceName, AccountName, ProcessCommandLine
```

---

### 4. 📁 **Detecting Compression & Exfiltration Attempts**
- **7z.exe** was used to **compress the stego images** into a zip file (**marketing_misc.zip**).
- File stored on **F:\\ drive** on guest workstation, indicating potential exfiltration.

**Query Used:**
```kql
DeviceFileEvents
| where DeviceName == "lobby-fl2-ae5fc"
| where InitiatingProcessCommandLine contains "suzie-and-bob.bmp" or InitiatingProcessCommandLine contains "bryce-fishing.bmp" or InitiatingProcessCommandLine contains "bryce-and-kid.bmp"
| order by Timestamp desc
| project Timestamp ,DeviceName, FileName, InitiatingProcessCommandLine, FolderPath, SHA256
```

---

### 5. 🔥 **Final Evidence** - Direct Link to Bryce Montgomery
- Timestamp **2025-02-05T08:57:32.2582822Z** revealed **Bryce** accessed & stored **marketing_misc.zip** in *F:\\Bryce Personal\\*.

**Query Used:**
```kql
DeviceFileEvents
| where SHA256 contains "07236346de27a608698b9e1ffef07b1987aa7fe8473aac171e66048ff322e2d6"
| order by Timestamp desc
| project Timestamp ,DeviceName, InitiatingProcessAccountName, FileName, PreviousFileName, InitiatingProcessCommandLine, FolderPath, SHA256
```

---

## 🔍 **Summary of Findings**
Bryce Montgomery attempted to **steal corporate data** using the following steps:
1. **Accessed & interacted with files**:
   - **Thumbprint:** `b3302e58be7eb604fda65d1d04a5e18325c66792`
2. **Used an additional workstation:**
   - **DeviceName:** `lobby-fl2-ae5fc`
3. **Steganography Tool Used:**
   - **Process:** `steghide.exe`
4. **Created Hidden Files:**
   - **Folder Path:** `C:\ProgramData\bryce-and-kid.bmp`
5. **Compressed Files:**
   - **SHA256 Hash:** `707f415d7d581edd9bce99a0429ad4629d3be0316c329e8b9ebd576f7ab50b71`
6. **Final Location of the Zip File:**
   - **Path:** `F:\marketing_misc.zip`
7. **Damning Evidence & Timestamp:**
   - **Location:** `F:\Bryce Personal\marketing_misc.zip`
   - **Timestamp:** `2025-02-05T08:57:32.2582822Z`

---

## 🛡️ **Response Actions Taken**
1. ❌ **Immediate User Suspension** - Bryce's access **revoked** pending legal action.
2. 🔴 **Incident Escalation** - Reported to **VP of Risk & Corporate Legal**.
3. 🔮 **Forensic Imaging** - Workstations & logs **secured** for further analysis.
4. 🛡️ **Review of DLP Policy** - Recommended **removing executive exemptions**.
5. 🔧 **Enhancing Security Controls** - Strengthening **SIEM rules** to detect similar threats.

---

🛡️ **Case Status:** **Escalated for Legal Review** 📈

