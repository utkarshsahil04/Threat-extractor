import re 
import os 
import logging 
from typing import List,Dict,Optional
from PyPDF2 import PdfReader
import sys

import spacy
import pdfplumber
import json
from transformers import AutoModelForTokenClassification, AutoTokenizer

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s :%(levelname)s: %(message)s',
    filename="threat_extraction.log"
)
class ThreatIntelligenceExtractor:
    def __init__(self):
        """
        Initialize the Threat Intelligence Extractor class.
        Load the SpaCy model and initialize the NER model.
        """
        try:
            self.nlp=spacy.load("en_core_web_sm")
        except OSError:
            logging.error("Spacy model not found")
        self.ner_model=None
        self.Ner_Tokenizer=None
        self._load_ner_model()
        
    def _load_ner_model(self):
        """
        Load the NER model using Hugging Face Transformers.
        """
        try:
            model_name="dislim/bert-base=ner"
            self.ner_tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.ner_model = AutoModelForTokenClassification.from_pretrained(model_name)
        except Exception as e:
            logging.error(f"Failed to laead Ner Model ; {e}")

    def validate_pdf(self,file_path):
        """
    Validate PDF file with comprehensive checks
    
    Args:
        file_path (str): Path to the PDF file
    
    Raises:
        FileNotFoundError: If file does not exist
        ValueError: If file is not a PDF
    """
        if not os.path.exists(file_path):
            logging.error(f"File not found : {file_path}")
            raise FileNotFoundError(f"FIle does not exist : {file_path}")
        if not file_path.lower().endswith('.pdf'):
            logging.error("Invalid file format")
            raise ValueError("Only Pdf file are Supported")
        if os.path.getsize(file_path)==0:
            logging.error("File is empty")
            raise ValueError("File is empty")

    def extract_text_from_pdf(self,file_path):
        """
        Extract text from a PDF file using pdfplumber.

        Args:
            file_path (str): Path to the PDF file.

        Returns:
            str: Extracted text from the PDF or None if unsuccessful.
        """
        self.validate_pdf(file_path)
        try:            
            with pdfplumber.open(file_path) as pdf:
                full_text=' '.join(page.extract_text() or '' for page in pdf.pages)
                if not full_text.strip():
                    logging.error("No text found in the PDF file")
                    return None
            return full_text
        except Exception as e:
            logging.error(f"Error: {e}")
            return None
        

    def extract_iocs(self,text):
        """
        Extract Indicators of Compromise (IOCs) from text.

        Args:
            text (str): Input text.

        Returns:
            dict: Extracted IOCs including IP addresses, domains, email addresses, and file hashes.
        """
        iocs = {
            
            "IP_Addresses": list(set(re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text))),
            "Domains": list(set(re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", text))),
            "Email_Addresses": list(set(re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", text))),
            "File_Hashes": list(set(re.findall(r"\b[a-fA-F0-9]{32,64}\b", text)))
        }
        
        return iocs
    def extract_ttps(self,text):
        """
        Extract Tactics, Techniques, and Procedures (TTPs) from text.

        Args:
            text (str): Input text.

        Returns:
            dict: Extracted tactics and techniques.
        """
        tactics = [
        ("TA0001", "Initial Access"),
        ("TA0002", "Execution"),
        ("TA0003", "Persistence"),
        ("TA0004", "Privilege Escalation"),
        ("TA0005", "Defense Evasion"),
        ("TA0006", "Credential Access"),
        ("TA0007", "Discovery"),
        ("TA0008", "Lateral Movement"),
        ("TA0009", "Collection"),
        ("TA0010", "Exfiltration"),
        ("TA0011", "Command and Control"),
        ("TA0012", "Impact"),
        ("TA0013", "Resource Development"),
        ("TA0014", "Execution Prevention"),
        ("TA0015", "Attribution"),
        ("TA0016", "Anti-Analysis"),
        ("TA0017", "Defense Posture"),
        ("TA0018", "Compromise Escalation"),
        ("TA0019", "Evasion"),
        ("TA0020", "Data Destruction"),
        ("TA0021", "Data Manipulation"),
        ("TA0022", "Data Encryption"),
        ("TA0023", "Disruption"),
        ("TA0024", "Infiltration"),
        ("TA0025", "Exploitation"),
        ("TA0026", "Malware Delivery"),
        ("TA0027", "Exfiltration Prevention"),
        ("TA0028", "Infiltration Prevention"),
        ("TA0029", "Redirecting Communications"),
        ("TA0030", "Stealth Techniques")
        ]
        techniques = [
            ("T1071", "Application Layer Protocol"),
        ("T1075", "Pass the Hash"),
        ("T1086", "PowerShell"),
        ("T1059", "Command and Control"),
        ("T1046", "Network Service Scanning"),
        ("T1057", "Process Discovery"),
        ("T1076", "Remote Desktop Protocol"),
        ("T1083", "File and Directory Discovery"),
        ("T1081", "Credentials from Web Browsers"),
        ("T1060", "Registry Run Keys / Startup Folder"),
        ("T1064", "Sudo Caching"),
        ("T1105", "Ingress Tool Transfer"),
        ("T1010", "Application Layer Protocol"),
        ("T1070", "Indicator Removal on Host"),
        ("T1011", "Exfiltration Over Command and Control Channel"),
        ("T1003", "Credential Dumping"),
        ("T1035", "Service Execution"),
        ("T1027", "Obfuscated Files or Information"),
        ("T1070", "Indicator Removal on Host"),
        ("T1048", "Windows Management Instrumentation"),
        ("T1081", "Credentials from Web Browsers"),
        ("T1005", "Data from Local System"),
        ("T1053", "Web Shell"),
        ("T1075", "Pass the Hash"),
        ("T1085", "Ransomware"),
        ("T1029", "Scheduled Task/Job"),
        ("T1012", "Query Registry"),
        ("T1087", "Control Panel Items"),
        ("T1036", "Masquerading"),
        ("T1079", "Application Layer Protocol"),
        ("T1019", "Remote Access Tools"),
        ("T1063", "Data from Information Repositories"),
        ("T1013", "Data Staged"),
        ("T1024", "Scheduled Task/Job"),
        ("T1088", "Exploitation for Privilege Escalation"),
        ("T1030", "Data from Network Shared Drive"),
        ("T1002", "Exfiltration Over Physical Medium"),
        ("T1072", "Application Layer Protocol"),
        ("T1014", "Data Staged"),
        ("T1007", "System Information Discovery"),
        ("T1025", "Application Layer Protocol"),
        ("T1033", "System Owner/User Discovery"),
        ("T1020", "Application Layer Protocol"),
        ("T1032", "Standard Application Layer Protocol")

        ]
        extracted_tactics = [t for t in tactics if any(t[1].lower() in line.lower() for line in text.splitlines())]
        extracted_techniques = [t for t in techniques if any(t[1].lower() in line.lower() for line in text.splitlines())]
        return {
            "Tactics": extracted_tactics,
            "Techniques": extracted_techniques
        }
    def extract_entities(self,text):
        """
        Extract named entities (organizations, locations, and persons) from text using SpaCy.

        Args:
            text (str): Input text.

        Returns:
            dict: Extracted entities.
        """

        doc=self.nlp(text)
        entities = {
            "Organizations": list(set([ent.text for ent in doc.ents if ent.label_ == "ORG"])),
            "Locations": list(set([ent.text for ent in doc.ents if ent.label_ == "GPE"])),
            "Persons": list(set([ent.text for ent in doc.ents if ent.label_ == "PERSON"]))
        }
        return entities

    def extract_threat(self,text):
        """
        Extract known threat actor names from text.

        Args:
            text (str): Input text.

        Returns:
            list: Extracted threat actor names.
        """
        threat=["Agrius","Ajax Security Team","Akira","ALLANITE","Andariel","Aodin Dragon","APT-C-23","APT-C-36","APT1","APT12","APT16","APT17","APT18","APT19","APT28","APT29","APT#","APT30","APT32","APT33","APT37","APT38","APT39","APT41","APT5","Aquatic Panda","Axiom","BackdoorDiplomacy","BITTER","BlackOasis","BlackTech","Blue Mockingbird","Bouncing Golf","BRONZE BUTLER","Carbanak","Chimera","Cinnamon Tempest","Cleaver","Cobalt Group","Confucius","CopyKittens","CURIUM","CyberAv3ngers","Daggerfly","Dark Caracal","Darkhotel","DarkHydrus","DarkHydrus","DarkVishnya","Deep Panda","Dragonfly","DragonOK","Earth Lusca","Elderwood","Ember Bear", "Equation","Evilnum","EXOTIC LILY","Ferocious Kitten","FIN10","FIN13","FIN4","FIN5","FIN6","FIN7","FIN8","Fox Kitten","GALLIUM","Gallmaker","Gamaeredon Group","GCMAN","GOLD SOUTHFIELD","Gorgon Group","Group5","HAFNIUM","HEXANE","Higaisa","INC Ransom","Inception","IndigoZebra","Indrik Spider","Kechang","Kimsuky","LAPSUS$","Lazarus Group","LazyScripter","Leafminer","Leviathan","Lotus Blossom","LuminpusMoth","Machete","Magic Hound","Malterio","menuPass","Metador","Moafee","Mofang","Molerats","Moonstone Sleet","Moses Staff","MoustachedBouncer","MuddyWater","Mustang Panda","Mustard Tempest","Naikon","NEODYMIUM","Nomadic Octopus","OilRig","Orangeworm","Patchwork","PittyTiger","PLATINUM","Play","POLONIUM","	Poseidon Group","PROMETHIUM","Putter Panda","Rancor","RedCurl","Rocke","RTM","Saint Bear","Sandworm Team","Scarlet Mimic","Scattered Spider","SideCopy","Sidewinder","Silence","Silent Librarian","SilverTerrier","Sowbug","Star Blizzard","Stealth Falcon","Strider","Suckfly","TA2541","TA359","TA505","TA551","TA577","TA578","TeanTNT","TEAMP.Veles","The White Company","Threat Group-1314","Threat Group-3390","Thrip","ToddyCat","Tonto Team","Transparent Tribe","Tropic Trooper","Turia","UNC788","Volatile Cedar","Volt Typhoon","Whitefly","Windigo","Windshift","Winnti Group","WInter Vivern","WIRTE","Wizard Spider","ZIRCONIUM"]  
        text=text.lower()
        extracted_threat=[t for t in threat if any(t.lower() in line for line in text.splitlines())]
        return extracted_threat


    def extract_malware(self,text):
        """
    Extract known malware names from the input text.

    This function uses a predefined list of malware names and their corresponding hashes.
    It searches for the malware names in the input text and returns a list of dictionaries
    containing the malware name, hashes, and tags.

    Args:
        text (str): The input text to search for malware names.

    Returns:
        list: A list of dictionaries containing the extracted malware information.
    """
        malware = [
        {
            'Name': 'Shamoon',
            'md5': 'vlfenvnkgn....',
            'sha1': 'bvdib....',
            'sha256': 'poherionnj....',
            'ssdeep': 'bgfnh....',
            'TLSH': 'bnfdnhg....',
            'tags': 'XYZ'
        },
        {
            'Name': 'WannaCry',
            'md5': 'abcd1234....',
            'sha1': 'efgh5678....',
            'sha256': 'ijkl9012....',
            'ssdeep': 'mnop3456....',
            'TLSH': 'qrst6789....',
            'tags': 'Ransomware, Worm'
        },
        {
            'Name': 'NotPetya',
            'md5': 'ghijklmn....',
            'sha1': 'opqrstuv....',
            'sha256': 'wxyz1234....',
            'ssdeep': 'abcd5678....',
            'TLSH': 'efgh9012....',
            'tags': 'Ransomware, Wiper'
        },
        {
            'Name': 'Emotet',
            'md5': 'abcdef12....',
            'sha1': 'ghijklm34....',
            'sha256': 'nopqrs56....',
            'ssdeep': 'tuvwxy78....',
            'TLSH': 'zabcd123....',
            'tags': 'Banking Trojan'
        },
        {
            'Name': 'TrickBot',
            'md5': 'mnopqrst....',
            'sha1': 'uvwxy1234....',
            'sha256': 'zabc5678....',
            'ssdeep': 'defg9012....',
            'TLSH': 'ghijk345....',
            'tags': 'Banking Trojan, Info Stealer'
        },
        {
            'Name': 'Stuxnet',
            'md5': 'xyz98765....',
            'sha1': 'mno87654....',
            'sha256': 'abcd1234....',
            'ssdeep': 'efgh4321....',
            'TLSH': 'ijkl0987....',
            'tags': 'Worm, Cyber Espionage'
        },
        {
            'Name': 'Zeus',
            'md5': 'lkjhgfdsa....',
            'sha1': 'qwertyuiop....',
            'sha256': 'asdfghjkl....',
            'ssdeep': 'zxcvbnmas....',
            'TLSH': 'qwerty123....',
            'tags': 'Banking Trojan'
        },
        {
            'Name': 'Conficker',
            'md5': 'lmno1234....',
            'sha1': 'pqrs5678....',
            'sha256': 'uvwxyz12....',
            'ssdeep': 'abcdef34....',
            'TLSH': 'ghijk987....',
            'tags': 'Worm'
        },
        {
            'Name': 'Sasser',
            'md5': 'qwerty5678....',
            'sha1': 'asdfgh9012....',
            'sha256': 'zxcvbn3456....',
            'ssdeep': 'lkjmn987....',
            'TLSH': 'fghijk2345....',
            'tags': 'Worm'
        },
        {
            'Name': 'Blaster',
            'md5': 'abcdef1234....',
            'sha1': 'ghijklm5678....',
            'sha256': 'nopqrst1234....',
            'ssdeep': 'mnop3456....',
            'TLSH': 'zyxw9876....',
            'tags': 'Worm'
        },
        {
            'Name': 'CryptoLocker',
            'md5': 'abcd1234....',
            'sha1': 'efgh5678....',
            'sha256': 'ijkl9012....',
            'ssdeep': 'mnop3456....',
            'TLSH': 'qrst6789....',
            'tags': 'Ransomware'
        },
        {
            'Name': 'Dridex',
            'md5': 'wxyz1234....',
            'sha1': 'abcd5678....',
            'sha256': 'efgh9012....',
            'ssdeep': 'ijkl3456....',
            'TLSH': 'mnop6789....',
            'tags': 'Banking Trojan'
        },
        {
            'Name': 'Locky',
            'md5': 'asdf1234....',
            'sha1': 'qwert5678....',
            'sha256': 'zxcv9012....',
            'ssdeep': 'lkjh3456....',
            'TLSH': 'mnop2345....',
            'tags': 'Ransomware'
        },
        {
            'Name': 'ZeAroAccess',
            'md5': 'asdf1234....',
            'sha1': 'qwert5678....',
            'sha256': 'zxcv9012....',
            'ssdeep': 'lkjh3456....',
            'TLSH': 'mnop2345....',
            'tags': 'Rootkit, Botnet'
        },
        {
            'Name': 'Mirai',
            'md5': 'ghijklm....',
            'sha1': 'nopqrst....',
            'sha256': 'uvwxyz....',
            'ssdeep': 'abcdef....',
            'TLSH': 'ghijk....',
            'tags': 'Botnet, IoT'
        },
        {
            'Name': 'Agent Tesla',
            'md5': 'qrst2345....',
            'sha1': 'wxyz6789....',
            'sha256': 'abcd5678....',
            'ssdeep': 'mnop3456....',
            'TLSH': 'ijkl2345....',
            'tags': 'Information Stealer'
        },
        {
            'Name': 'Kovter',
            'md5': 'mnop3456....',
            'sha1': 'wxyz6789....',
            'sha256': 'abcdef12....',
            'ssdeep': 'ijkl9012....',
            'TLSH': 'qrst9876....',
            'tags': 'Ad Fraud, Trojan'
        },
        {
            'Name': 'Red October',
            'md5': 'abcd9876....',
            'sha1': 'ijkl2345....',
            'sha256': 'mnop5678....',
            'ssdeep': 'wxyz3456....',
            'TLSH': 'abcd1234....',
            'tags': 'Cyber Espionage, APT'
        },
        {
            'Name': 'APT28 (Fancy Bear)',
            'md5': 'qwerty12....',
            'sha1': 'asdfgh34....',
            'sha256': 'zxcvbn56....',
            'ssdeep': 'lkjhg123....',
            'TLSH': 'mnop7890....',
            'tags': 'APT, Cyber Espionage'
        }
    ]
        lower_text=text.lower()
        found_malware=[]
        for malware_entry in malware:
            malware_name=malware_entry['Name'].lower()
            clean_name=re.sub(r'[^\w\s]','',malware_name)
            if re.search(r'\b'+re.escape(clean_name)+ r'\b' ,lower_text):
                found_malware.append(malware_entry)
        return found_malware

    def extract_target_entities(self,text):
        """
        Extract targeted entities from the input text.

        Args:
            text (str): Input text.

        Returns:
            list: Extracted targeted entities.
        """
        Targeted_Entities = [
    # Energy Companies
    "Energy Companies",
    "Oil and Gas Companies",
    "Renewable Energy Providers",
    "Electric Utilities",
    "Nuclear Power Plants",
    "Coal Mining Companies",
    "Natural Gas Providers",
    "Hydrogen Energy Producers",

    # Energy Infrastructure
    "Energy Infrastructure",
    "Power Grids",
    "Refineries",
    "Wind and Solar Farms",
    "Hydroelectric Dams",
    "Liquefied Natural Gas (LNG) Terminals",
    "Offshore Oil Platforms",
    "Oil Pipelines",
    "Gas Pipelines",
    "District Heating Systems",

    # Energy Equipment Manufacturers
    "Solar Panel Manufacturers",
    "Wind Turbine Manufacturers",
    "Battery Storage Companies",
    "Power Transmission Equipment Makers",
    "Smart Grid Equipment Manufacturers",
    "Energy Metering Device Producers",
    "Geothermal Plant Equipment Manufacturers",
    "Nuclear Reactor Component Manufacturers",
    "Turbine Blade Manufacturers",

    # Government Bodies/Regulatory Agencies
    "Government Bodies/Regulatory Agencies",
    "Energy Regulatory Commissions",
    "Environmental Protection Agencies",
    "Ministry of Energy",
    "International Energy Agencies",
    "Department of Energy",
    "Nuclear Regulatory Commissions",
    "Renewable Energy Policy Councils",
    "Climate Action Agencies",

    # Energy Consumers
    "Large Industrial Users",
    "Residential Consumers",
    "Commercial Buildings and Facilities",
    "Electric Vehicle Charging Stations",
    "Energy Efficiency Service Providers",
    "High Energy-Consuming Data Centers",
    "Cryptocurrency Mining Facilities",
    "Electric Public Transportation Systems",

    # Energy Traders and Brokers
    "Futures and Commodities Traders",
    "Market Analysts and Consultants",
    "Energy Investment Firms",
    "Carbon Credit Traders",
    "Energy Trading Platforms",
    "Renewable Energy Certificate (REC) Markets",

    # Energy Research and Development
    "Universities and Research Institutions",
    "Think Tanks and Consulting Firms",
    "Innovation Hubs for Clean Energy",
    "Energy Technology Startups",
    "Research Labs for Advanced Energy Systems",
    "Smart City Development Programs",

    # Cybersecurity Targets in Energy
    "Critical Infrastructure Networks",
    "SCADA Systems",
    "Energy Storage Systems",
    "Smart Grid Systems",
    "IoT Devices in Energy Systems",
    "Energy Management Software Providers",
    "Industrial Control Systems (ICS)",
    "Building Management Systems (BMS)",
    "Substation Automation Systems",
    "Telemetry Systems for Energy Monitoring",

    # Energy Contractors
    "Companies involved in energy plant construction and maintenance",
    "Engineering, Procurement, and Construction (EPC) Contractors",
    "Engineering Consultants in Energy Projects",
    "Energy Infrastructure Project Managers",
    "Renewable Energy Project Developers",
    "Power Line Construction Contractors",
    "Grid Modernization Contractors",

    # Alternative Energy Companies
    "Geothermal Energy Providers",
    "Biomass Energy Companies",
    "Tidal and Wave Energy Companies",
    "Hydrogen Fuel Cell Developers",
    "Biofuel Manufacturers",
    "Algae-Based Energy Startups",

    # Electricity Distribution Companies
    "Electricity Distribution Companies",
    "Smart Meter Providers",
    "Electricity Retailers",
    "Load Balancing Service Providers",
    "Demand Response Aggregators",

    # Energy Financing and Investment Institutions
    "Venture Capital Firms in Clean Tech",
    "Private Equity Firms",
    "Green Bond Issuers",
    "Clean Energy Investment Funds",
    "Public-Private Partnerships in Energy",

    # Energy Legal and Compliance Firms
    "Energy Law Firms",
    "Regulatory Compliance Advisors",
    "Environmental Compliance Consultants",
    "Legal Advisors for Renewable Energy Projects",

    # Energy Policy Makers
    "Energy Advocacy Groups",
    "International Energy Organizations",
    "Policy Institutes for Climate Change",
    "Renewable Energy Councils",
    "Carbon Neutrality Task Forces",

    # Energy Management System Providers
    "Building Energy Management Systems",
    "Energy Auditing Companies",
    "Smart Building Solution Providers",
    "Facility Management Companies",

    # Energy Efficiency Product Manufacturers
    "LED Lighting Companies",
    "Energy Efficient Appliance Manufacturers",
    "Smart Thermostat Producers",
    "Energy Recovery Ventilation (ERV) System Providers",
    "High-Efficiency HVAC Manufacturers",

    # Utility Infrastructure Providers
    "Power Line Installation Companies",
    "Gas Pipeline Construction Companies",
    "Utility Substation Equipment Providers",
    "Electric Utility Maintenance Contractors",
    "Hydroelectric Dam Maintenance Firms",

    # Energy Storage Technology Providers
    "Lithium-Ion Battery Manufacturers",
    "Grid-Scale Energy Storage Providers",
    "Energy Storage System Integrators",
    "Flow Battery Manufacturers",
    "Compressed Air Energy Storage (CAES) Companies",
    "Thermal Energy Storage System Providers",

    # Emerging Technology Companies
    "Blockchain for Energy Startups",
    "Artificial Intelligence in Energy Companies",
    "Digital Twin Technology Providers for Energy",
    "Quantum Computing Applications in Energy",

    # Energy Education and Training
    "Vocational Training Institutes for Energy Technicians",
    "Universities with Renewable Energy Programs",
    "Energy Workforce Development Organizations",

    # International Energy Organizations
    "International Renewable Energy Agency (IRENA)",
    "International Atomic Energy Agency (IAEA)",
    "Organization of the Petroleum Exporting Countries (OPEC)",
    "World Energy Council",
    "Energy Charter Treaty Organizations",
    "United Nations Framework Convention on Climate Change (UNFCCC)"
]


        text=text.lower()
        extracted_target_entities=[t for t in Targeted_Entities if any (t.lower() in word for word in text.split())]
        return extracted_target_entities


    def process_pdf_for_threat_data(self,file_path, output_file_path):
        """
        Process a PDF file to extract threat intelligence data and save it to a JSON file.

        Args:
            file_path (str): Path to the input PDF file.
            output_file_path (str): Path to save the output JSON file.

        Returns:
            dict: Extracted threat intelligence data or None if unsuccessful.
        """
        try:
            pdf_text = self.extract_text_from_pdf(file_path)
            if not pdf_text:
                logging.warning("No text extracted from the pdf ")
                return None
            else:
                print("Text extracted successfully. Extracting threat data...")
            threat_data = {
                "IOCs": self.extract_iocs(pdf_text),
                "TTPs": self.extract_ttps(pdf_text),
                "Threat Actor": self.extract_threat(pdf_text),
                "Entities":self.extract_entities(pdf_text),
                "Malware":self.extract_malware(pdf_text),
                "Target Entities": self.extract_target_entities(pdf_text),
            }
            
            if not any(threat_data.values()):
                logging.warning("No threat data extracted from the pdf ")
            with open(output_file_path,'w') as json_file:  
                json.dump(threat_data,json_file,indent=4)
            logging.info(f"Threat Data has been added succesfully in {output_file_path}")
            return threat_data
        except Exception as e:
            logging.error( f"Error: Could not extract text from the PDF.{e}")
            return None
    

def main():
    """
    Main function to handle script execution from the command line.
    """
    if len(sys.argv) != 3:
        print("Usage: python threat_extractor.py <input_pdf_path> <output_json_path>")
        sys.exit(1)
    extractor =ThreatIntelligenceExtractor()
    input_pdf = sys.argv[1]
    
    output_json = sys.argv[2]
    
    result  = extractor.process_pdf_for_threat_data(input_pdf, output_json)
    if result:

        print(json.dumps(result, indent=4))
    else:
        print("Failed to extract threat intelligence.")

if __name__=="__main__":
    main()