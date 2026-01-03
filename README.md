# MyGB Guestbook

![](https://static.mighil.com/images/2026/mygb.webp)

A simple and fast guestbook powered by Cloudflare services.

## Features

- **Serverless**: Runs on Cloudflare Workers (Edge network).
- **Database**: Uses Cloudflare D1 (SQL at the edge).
- **Spam Protection**: Built-in Cloudflare Turnstile integration.
- **Embeddable**: Drop a simple JS snippet on any website to display the guestbook.
- **AI-Friendly**: Code is commented well enough to help you (or your AI assistant) customize it easily.

## Getting Started

- Read the [quick setup guide](https://mighil.com/mygb) if you are new to Cloudflare Workers 
- Read the [getting started guide](getting-started.md) if you're a developer.

## How it Works

1.  **Backend**: A single `worker.js` file handles everything (API, HTML rendering, Admin panel).
2.  **Frontend**: Vanilla JavaScript (no frameworks) for the embed widget.
3.  **Storage**: SQLite database (D1) stores entries and settings.

## License

**GNU AGPL v3** - Open source. Keep it free.
