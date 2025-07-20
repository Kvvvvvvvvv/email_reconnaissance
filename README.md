<<<<<<< HEAD
# email_reconnaissance
=======
# Email Security Analyzer

A comprehensive email security and risk analysis tool that helps identify potential security risks and provides detailed information about email addresses.

## Features

- Email format validation
- Domain analysis (MX, SPF, DMARC records)
- Data breach checking
- Social media presence detection
- Risk score calculation
- Security recommendations
- Modern, responsive UI with Tailwind CSS

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd email-security-analyzer
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Start the application:
```bash
python app.py
```

2. Open your browser and navigate to:
```
http://localhost:5000
```

3. Enter an email address to analyze its security status and potential risks.

## API Usage

The application also provides a REST API endpoint for programmatic access:

```bash
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"email": "example@domain.com"}'
```

## Security Features

- Email format validation
- Domain existence verification
- MX record checking
- SPF record validation
- DMARC record checking
- Data breach history
- Social media presence detection
- Risk score calculation
- Security recommendations

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and security assessment purposes only. Always ensure you have proper authorization before analyzing any email addresses. 
>>>>>>> a342257 (Initial)
