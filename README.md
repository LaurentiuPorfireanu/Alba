# Network Security AI

## Overview
Network Security AI is a comprehensive, machine learning-driven system designed to monitor network traffic, detect anomalous behavior, and simulate potential cyber threats. By leveraging advanced artificial intelligence models, the system can identify malicious activities in real-time and trigger automated defensive countermeasures. It features a microservices-based architecture, fully containerized for scalable deployment, and includes a web-based dashboard for intuitive monitoring and visualization.

## Core Features

*   **AI-Powered Anomaly Detection:** Utilizes trained neural network models (PyTorch) to analyze network traffic patterns and detect deviations indicative of unauthorized access or cyber attacks.
*   **Automated Defense System:** An intelligent module capable of evaluating detected anomalies and deploying simulated defense mechanisms to mitigate threats.
*   **Attack Simulation & Traffic Generation:** Built-in tools to generate synthetic network traffic and simulate various attack vectors, allowing for continuous testing and refinement of the AI models.
*   **Real-Time Network Monitoring:** Dedicated monitoring scripts that capture, parse, and log network traffic data into structured formats (JSON) for analysis.
*   **Web Dashboard:** A user-friendly web interface that provides security administrators with real-time insights, metrics, and alerts regarding network health and detected anomalies.
*   **Microservices Architecture:** The project is modularized using Docker, separating traffic generation, monitoring, AI inference, and web serving into distinct, isolated containers.

## Project Architecture

The repository is structured to separate data logging, AI modeling, application logic, and container orchestration:

*   **`models/`**: The core AI engine of the project. It contains the Python definitions for the Machine Learning architectures (`anomaly_detector.py`, `attack_simulator.py`, `defense_system.py`) as well as their pre-trained PyTorch weight files (`.pth`).
*   **`docker/`**: Contains specific Dockerfiles (`Dockerfile.monitor`, `Dockerfile.traffic`) and configuration files (`nginx.conf`) required to build the individual microservices. It also includes the specific scripts used by these containers, such as `traffic_generator.py`.
*   **`web_app/`**: Holds the frontend and backend logic for the web dashboard (`app.py`), along with HTML templates (`templates/dashboard.html`) for visualizing the security data.
*   **`src/`**: Contains the core source code for the network monitoring modules (`network_monitor.py`).
*   **`data/`**: The persistent storage directory where network traffic logs (`network_traffic.json`) are recorded and read by the AI and web dashboard.
*   **`main.py`**: The central execution script that ties the project's sub-components together.
*   **`docker-compose.yml` & `Dockerfile`**: Orchestration and build files defining the multi-container environment and the main application dependencies.
*   **`requirements.txt`**: A comprehensive list of the Python packages and dependencies required by the system, including AI libraries, web frameworks, and network tools.

## Technologies Used

*   **Machine Learning:** PyTorch (Deep Learning models for detection and defense)
*   **Web Framework:** Python Web Framework (likely Flask/FastAPI based on the `app.py` structure)
*   **Containerization:** Docker & Docker Compose
*   **Reverse Proxy:** Nginx
*   **Data Serialization:** JSON (for robust log handling)
