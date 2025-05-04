# Network IDS Interface

A comprehensive network monitoring and intrusion detection system with Python backend for packet analysis and Node.js frontend server.

## Project Structure

```
network-ids/          
├── ids.py        
├── server/           # Node.js web server
│   ├── index.js      # Server entry point
│   ├── package.json  # Node dependencies
│   └── .env          # Environment variables 
└── README.md         # This file
```

## Setup Instructions

### Python Backend Setup

1. Install Python dependencies:

```bash
pip install scapy requests argparse logging
```

2. Run the IDS script:

```bash
python python/ids.py -i eth0
```

Replace `eth0` with your network interface.

### Node.js Server Setup

1. Navigate to the server directory:

```bash
cd server
```

2. Install Node.js dependencies:

```bash
npm install
```

3. Create a `.env` file in the server directory:

```bash
echo "MONGOOSE_KEY=your_mongodb_connection_string" > .env
```

Replace `your_mongodb_connection_string` with your actual MongoDB connection string.

4. Start the server:

```bash
node index.js
```

The server should now be running at http://localhost:3000 (or your configured port).

## Usage

1. Start the Node.js server first to ensure the database connection is established.
2. Run the Python IDS script to begin collecting and analyzing network traffic

## Features

- Real-time packet capture and analysis
- Anomaly detection
- Event logging and alerting
- Historical data storage in MongoDB

## Requirements

- Python 3.8+
- Node.js 14+
- MongoDB database
- Network interface with promiscuous mode access (for comprehensive monitoring)

## Configuration

Additional configuration options can be found in the respective component directories.
