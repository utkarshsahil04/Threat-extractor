
# Threat Intelligence Extractor

This Python application extracts threat intelligence data from PDF files, including Indicators of Compromise (IOCs), Tactics, Techniques, Procedures (TTPs), named entities, threat actors, and malware. The extracted data is structured and saved as a JSON file.

## Features
- **PDF Text Extraction:** Extracts text content from PDF files using `pdfplumber`.
- **IOC Extraction:** Identifies and extracts IP addresses, domain names, email addresses, and file hashes.
- **TTP Detection:** Matches predefined MITRE ATT&CK tactics and techniques from the text.
- **Named Entity Recognition (NER):** Extracts named entities (e.g., organizations, locations, persons) using SpaCy.
- **Threat Actor Identification:** Detects known threat actor names from a predefined list.
- **Malware Analysis:** Matches known malware names and associated attributes.
- **Target Entities Detection:** Identifies specific targets like energy companies or critical infrastructure entities.
- **Logging:** Maintains detailed logs for debugging and tracking.

## Prerequisites
- Python 3.8 or later is required.

### Required Python Libraries
The following Python libraries are required to run the application:
- `PyPDF2`: For basic PDF operations.
- `pdfplumber`: For extracting text from PDF files.
- `spacy`: For natural language processing and NER.
- `transformers`: For using Hugging Face pre-trained models.

## Installation Guide
### Step 1: Clone or Download the Repository
If you received the files directly, place them in a working directory on your local machine.

### Step 2: Install Python
Make sure Python 3.8 or later is installed. You can download it from [python.org](https://www.python.org/downloads/).

### Step 3: Install Dependencies
1. Open a terminal or command prompt.
2. Navigate to the directory containing the `requirements.txt` file.
3. Run the following command to install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Step 4: Download SpaCy Model
The application requires the `en_core_web_sm` model. Install it by running:
```bash
python -m spacy download en_core_web_sm
```

## How to Use
1. Place the PDF file you want to process in the working directory.
2. Run the application with the following command:
   ```bash
   python threat_extractor.py <input_pdf_path> <output_json_path>
   ```
   - `<input_pdf_path>`: Path to the PDF file.
   - `<output_json_path>`: Path where the output JSON file will be saved.

### Example
```bash
python threat_extractor.py example.pdf output.json
```

## Output Details
The output JSON file contains the following sections:
- **IOCs:** Extracted IP addresses, domain names, email addresses, and file hashes.
- **TTPs:** Matched MITRE ATT&CK tactics and techniques.
- **Entities:** Extracted organizations, locations, and persons.
- **Threat Actors:** Identified known threat actor names.
- **Malware:** Matched malware names with attributes like MD5 and SHA1 hashes.
- **Target Entities:** Detected target entities like energy companies or critical infrastructure.

## Troubleshooting
- Ensure the input PDF file exists and is not empty.
- Reinstall dependencies if you encounter import errors:
  ```bash
  pip install -r requirements.txt
  ```
- Verify that the `en_core_web_sm` SpaCy model is installed:
  ```bash
  python -m spacy download en_core_web_sm
  ```
- Check the logs in `threat_extraction.log` for detailed error messages.

## Logging
Logs are saved to `threat_extraction.log` in the working directory. They include details about successful operations and errors.

## License
This project is intended for educational and research purposes only.

## Contact
For any issues or inquiries, feel free to reach out to the project maintainer.
