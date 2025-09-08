# 🔎 Agentic AI Terminal Search

This project is an Agentic AI that lets you search the internet directly from your terminal.
It is built on top of the Strands Agents
 framework and primarily uses the http_request tool to make API calls, fetch web data, and call local HTTP servers.

## 🚀 Features

🌐 Direct Internet Search – Query the web right from your terminal.

⚡ Agentic AI – Uses Strands Agents for planning and tool orchestration.

🛠 http_request Tool – Supports APIs, web data fetching, local servers, authentication, and sessions.


## 📂 Project Structure

├── extracted_info/\
│ └── 9_Advanced_Running_Metrics_You... # Example extracted info file\
│\
├── my_agent/\
│ ├── init.py # Package initializer\
│ ├── .env.example # Environment variable template\
│ ├── .gitignore # Ignore env files and other artifacts\
│ ├── agent.py # Example agent + tools\
│ ├── requirements.txt # Dependencies\
│ └── test.py # Main entrypoint: internet search utility\
│\
├── summaries/\
│ ├── 9_Advanced_Running_Metrics_You... # Example Summary file\
│ └── Running_Metrics_Guide_8_Stats_to...# Another summary file\
│\
├── venv/ # Virtual environment\
│\
├── bookmarks.json # Bookmarks storage\
└── README.md # Project documentation\

## ⚙️ Installation

Clone this repository:
```
git clone <your-repo-url>

cd <your-repo-name>
```


Create and activate a virtual environment (recommended):

``` python -m venv venv
source venv/bin/activate   # macOS/Linux
venv\Scripts\activate      # Windows
```


Install dependencies:

```
pip install -r requirements.txt
```


## ▶️ Usage

Run the search agent:

```
python3 -u my_agent/test.py
```

Then enter your query when prompted:

```
🔎 Enter your search query: swimming classes in Singapore
```


The agent will return the top results directly in your terminal.
