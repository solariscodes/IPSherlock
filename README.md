# WHOIS Lookup Tool

A web application that allows users to look up detailed information about IP addresses and hostnames. The application provides comprehensive information including DNS records, WHOIS data, geolocation, and network information.

## Features

- IP to hostname resolution
- Hostname to IP resolution
- Detailed IP information (ASN, geolocation, network)
- DNS record lookup (A, MX, NS, TXT)
- WHOIS information
- Clean, responsive UI

## Technologies Used

- **Backend**: Python with Flask
- **Frontend**: HTML, CSS, JavaScript
- **External APIs**: ipapi.co for geolocation data
- **Python Libraries**: python-whois, dnspython, ipwhois, requests

## Local Development

1. Clone the repository
2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Run the application:
   ```
   python app.py
   ```
4. Open your browser and navigate to `http://localhost:5000`

## Deployment to Heroku

This application is configured for deployment to Heroku:

1. Create a Heroku account if you don't have one
2. Install the Heroku CLI
3. Login to Heroku:
   ```
   heroku login
   ```
4. Create a new Heroku app:
   ```
   heroku create your-app-name
   ```
5. Deploy the application:
   ```
   git push heroku main
   ```

## Project Structure

```
whois-app/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── Procfile              # Heroku deployment configuration
├── runtime.txt           # Python version for Heroku
├── static/
│   ├── css/
│   │   └── style.css     # Shared styles for both pages
│   └── js/
│       └── script.js     # Frontend JavaScript
└── templates/
    ├── index.html        # Homepage with search box
    └── results.html      # Results page
```

## License

This project is open source and available under the MIT License.
