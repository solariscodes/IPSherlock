# IPSherlock - IP & Domain Intelligence Tool

A detective-themed web application that provides comprehensive information about IP addresses and domain names. IPSherlock delivers detailed intelligence including DNS records, WHOIS data, geolocation, and network information with a sleek, user-friendly interface.

🔍 **Live Application**: [https://ipsherlock.com/](https://ipsherlock.com/)

## Features

- Comprehensive IP address intelligence
- Detailed domain name information
- DNS record lookup (A, MX, NS, TXT)
- WHOIS data with registrar information
- Geolocation mapping with country, city, and coordinates
- Network information including ASN and organization
- Copy to clipboard functionality for easy data sharing
- Export results to CSV for further analysis
- Clean, detective-themed responsive UI
- Secure search logging system

## Technologies Used

- **Backend**: Python with Flask
- **Frontend**: HTML, CSS, JavaScript
- **Deployment**: Railway platform
- **External APIs**: Multiple geolocation services with fallback capability
- **Python Libraries**: python-whois, dnspython, ipwhois, requests
- **Version Control**: Git/GitHub

## Local Development

1. Clone the repository:
   ```
   git clone https://github.com/solariscodes/IPSherlock.git
   ```
2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Run the application:
   ```
   python app.py
   ```
4. Open your browser and navigate to `http://localhost:5000`

## Deployment on Railway

This application is deployed on Railway:

1. Fork or clone this repository
2. Create a Railway account at [railway.app](https://railway.app)
3. Create a new project and connect to your GitHub repository
4. Railway will automatically detect the Python/Flask application
5. The application will use the PORT environment variable provided by Railway
6. Custom domains can be configured in the Railway dashboard

## Project Structure

```
ipsherlock/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── Procfile               # Railway/Gunicorn configuration
├── runtime.txt            # Python version specification
├── logs/                  # Search logs directory (local development)
├── static/
│   ├── css/
│   │   └── style.css      # Detective-themed styles
│   ├── js/
│   │   └── script.js      # Frontend functionality
│   └── img/
│       └── logo.svg       # IPSherlock detective logo
└── templates/
    ├── index.html         # Homepage with search box
    └── results.html       # Detailed results page
```

## License

This project is open source and available under the MIT License.
