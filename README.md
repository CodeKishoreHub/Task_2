INTERN COMPANY : CODETECH IT SOLUTIONS

NAME : KISHORE NARAYANAN K

INTERN ID : CT06DF297

DOMAIN : CYBER SECURITY AND ETHICAL HACKING

DURATION : 6 WEEKS

MENTOR : NEELA SANTHOSH

About this Network Inscpector Tool
This Network Inspector Tool is a simple yet powerful web-based application designed for cybersecurity and network auditing. It's built using modern web technologies like HTML5 and CSS3, with a Python-powered Flask backend that handles the heavy lifting. Essentially, it helps users perform basic penetration testing and reconnaissance tasks, making it an invaluable tool for those looking to analyze and assess network security.The way it works is straightforward—users enter an IP address or domain, and the tool runs several backend processes using well-known libraries like Nmap for port scanning and Requests for probing websites. It even employs pattern-matching techniques to identify potential security vulnerabilities such as SQL injection (SQLi) or Cross-Site Scripting (XSS). The results are neatly displayed using Jinja2 templating, ensuring a clean and easy-to-read format.Beyond scanning ports and detecting services, this tool provides deeper insights into a target's security setup. It fetches important HTTP headers, which can reveal server technologies, misconfigurations, or missing security defenses. The frontend has been designed with a modern aesthetic—using flexbox for layout, media queries for responsive design, and smooth transitions for a better user experience. A JavaScript-powered loading spinner keeps users engaged while scans are running in the background.

Output Results : 

![Image](https://github.com/user-attachments/assets/431fc698-42cd-41ad-837a-0471e2d294e5)
![Image](https://github.com/user-attachments/assets/68f95fee-1028-4e45-bbbc-1e755609a492)

On the backend, security is a top priority. The Flask app processes POST requests safely, leveraging Python’s capabilities to prevent command injection attacks. Plus, it's highly modular, meaning it can be expanded to include features like SSL certificate validation, directory enumeration, or robots.txt analysis. This flexibility makes it useful for ethical hacking, student learning, or even integrating into DevSecOps workflows. Scan results can be stored as JSON or text, making them compatible with SIEM tools for further analysis.

Usability and accessibility have also been considered. The input fields include validation checks, ensuring smooth user interactions, and results are displayed in a scrollable, preformatted block for easy reading—even on smaller screens. Thanks to its lightweight design, the app can be hosted on Heroku, AWS EC2, or Render, and even containerized using Docker, making deployment a breeze.

Ultimately, this Network Inspector Tool is a practical yet educational application that blends web development with cybersecurity. Whether you're a security analyst, ethical hacker, or student eager to understand how reconnaissance works, this tool offers an intuitive and effective way to audit networks. With its user-friendly interface and robust backend capabilities, it’s a valuable asset for anyone interested in security assessments, internal audits, or web application hardening.
