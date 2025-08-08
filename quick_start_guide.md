# 🚀 Quick Start Guide

Get the LLM Prompt Risk Scanner running in under 5 minutes!

## 🎯 Option 1: Automated Setup (Recommended)

### Step 1: Download and Extract
```bash
# Download the project
git clone https://github.com/your-username/llm-prompt-risk-scanner.git
cd llm-prompt-risk-scanner
```

### Step 2: Run Setup Script
```bash
# Run the interactive setup
python setup.py
```

The setup script will:
- ✅ Check Python version
- 📦 Install all dependencies
- 🔑 Guide you through API key configuration
- 🧪 Test the installation
- 🚀 Give you the command to start

### Step 3: Start the Scanner
```bash
streamlit run app.py
```

**That's it!** 🎉 Your scanner will open at `http://localhost:8501`

---

## ⚡ Option 2: Manual Setup (Advanced Users)

### Prerequisites
- Python 3.8+
- At least one API key from supported providers

### Quick Commands
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Copy environment template
cp .env.example .env

# 3. Edit .env file with your API keys
nano .env  # or use your preferred editor

# 4. Run the application
streamlit run app.py
```

---

## 🔑 Get Your API Keys (Choose at least one)

### 🌟 Together AI (Recommended for Beginners)
- **Free Tier**: 5M tokens/month
- **Sign up**: [api.together.xyz](https://api.together.xyz)
- **Why choose**: Free, fast, multiple models
- **Setup time**: 2 minutes

### 🤖 OpenAI
- **Pricing**: Pay-per-use
- **Sign up**: [platform.openai.com](https://platform.openai.com)
- **Why choose**: Most popular, reliable
- **Setup time**: 3 minutes (requires billing)

### 🧠 Anthropic Claude
- **Free Credit**: $5 to start
- **Sign up**: [console.anthropic.com](https://console.anthropic.com)
- **Why choose**: High quality analysis
- **Setup time**: 2 minutes

### 💡 DeepSeek
- **Pricing**: Very competitive
- **Sign up**: [platform.deepseek.com](https://platform.deepseek.com)
- **Why choose**: Cost-effective
- **Setup time**: 2 minutes

---

## 🐳 Option 3: Docker (One-Click Deploy)

Perfect for isolated environments or production deployments.

### Quick Docker Setup
```bash
# 1. Clone repository
git clone https://github.com/your-username/llm-prompt-risk-scanner.git
cd llm-prompt-risk-scanner

# 2. Create .env file with your API keys
cp .env.example .env
# Edit .env with your keys

# 3. Run with Docker Compose
docker-compose up -d

# 4. Access at http://localhost:8501
```

### Stop the Container
```bash
docker-compose down
```

---

## 🧪 Test Your Setup

### 1. Check API Keys
The app will show you which providers are available:
```
✅ Available providers: Together AI, OpenAI
```

### 2. Run a Test Scan
1. Select a provider (e.g., "Together AI")
2. Choose a model (e.g., "Llama 3.3 70B Turbo")
3. Keep the default test prompt
4. Click "🔍 Scan Prompt"

### 3. Expected Results
You should see:
- **Heuristic Analysis**: Pattern-based detection
- **AI Analysis**: Detailed security assessment

---

## 🚨 Troubleshooting

### Common Issues

#### ❌ "No API keys found"
**Solution**: Make sure your `.env` file has at least one API key:
```env
TOGETHER_API_KEY=your_actual_key_here
```

#### ❌ "Missing dependencies"
**Solution**: Reinstall requirements:
```bash
pip install -r requirements.txt
```

#### ❌ "Port 8501 already in use"
**Solution**: Use a different port:
```bash
streamlit run app.py --server.port 8502
```

#### ❌ "API Error: Unauthorized"
**Solution**: Check your API key is correct and has sufficient credits

### Still Having Issues?
1. 📖 Check the full [README.md](README.md)
2. 🐛 Open an [issue on GitHub](https://github.com/your-username/llm-prompt-risk-scanner/issues)
3. 💬 Join our [discussions](https://github.com/your-username/llm-prompt-risk-scanner/discussions)

---

## 🎯 What's Next?

### Explore Features
- 🔍 Try different test prompt categories
- 🤖 Compare results across AI providers
- 📊 Analyze your own prompts
- 🛡️ Learn about OWASP LLM Top 10

### Customize
- Add your own risk patterns
- Create custom test prompts
- Integrate with your CI/CD pipeline
- Export results for reporting

### Share & Contribute
- ⭐ Star the repository
- 🐛 Report bugs or suggest features
- 🤝 Contribute improvements
- 📢 Share with your team

---

## 📞 Need Help?

- 📧 **Email**: your.email@domain.com
- 💬 **GitHub Discussions**: Ask questions and share ideas
- 🐛 **Issues**: Report bugs or request features
- 🌐 **Website**: More tools and resources

---

<div align="center">

**🛡️ Happy Scanning!**

*Built with ❤️ by Syed Ali Turab*

</div>