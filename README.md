# 🔎 Agentic AI Terminal Search

This project is an Agentic AI that lets you search the internet directly from your terminal.
It is built on top of the Strands Agents
 framework and primarily uses the http_request tool to make API calls, fetch web data, and call local HTTP servers.

## 🚀 Features

🌐 Direct Internet Search – Query the web right from your terminal.

⚡ Agentic AI – Uses Strands Agents for planning and tool orchestration.

🛠 http_request Tool – Supports APIs, web data fetching, local servers, authentication, and sessions.

🔧 Custom Tools – Includes an example letter_counter tool.

## 📂 Project Structure

├── __init__.py          # Package initializer

├── agent.py             # Example agent + tools

├── test.py              # Main entrypoint: internet search utility

├── requirements.txt     # Dependencies

├── .env.example         # Environment variable template

├── .gitignore           # Ignore env files and other artifacts

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
python test.py
```

Then enter your query when prompted:

```
🔎 Enter your search query: swimming classes Singapore
```


The agent will return the top results directly in your terminal.
