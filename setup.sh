#!/bin/bash
# Setup script for CyberDrill dependencies

set -e

echo "========================================="
echo "CyberDrill Setup Script"
echo "========================================="

# Detect OS
OS="$(uname -s)"
case "${OS}" in
    Linux*)     OS_TYPE=Linux;;
    Darwin*)    OS_TYPE=Mac;;
    CYGWIN*)    OS_TYPE=Windows;;
    MINGW*)     OS_TYPE=Windows;;
    *)          OS_TYPE="UNKNOWN:${OS}"
esac

echo "Detected OS: ${OS_TYPE}"

# Function to install Linux dependencies
install_linux_deps() {
    echo "Installing Linux dependencies..."
    
    if command -v apt-get &> /dev/null; then
        # Debian/Ubuntu
        sudo apt-get update
        sudo apt-get install -y \
            python3 python3-pip python3-venv \
            libgl1-mesa-glx libglib2.0-0 libsm6 libxext6 \
            libxrender-dev libgomp1 libxcb-xinerama0 \
            iputils-ping traceroute nmap tcpdump
            
    elif command -v yum &> /dev/null; then
        # RHEL/CentOS
        sudo yum install -y \
            python3 python3-pip \
            mesa-libGL glib2 libSM libXext \
            libXrender libgomp libxcb \
            iputils traceroute nmap tcpdump
            
    elif command -v dnf &> /dev/null; then
        # Fedora
        sudo dnf install -y \
            python3 python3-pip \
            mesa-libGL glib2 libSM libXext \
            libXrender libgomp libxcb \
            iputils traceroute nmap tcpdump
            
    elif command -v pacman &> /dev/null; then
        # Arch
        sudo pacman -S --noconfirm \
            python python-pip \
            mesa glib2 libsm libxext \
            libxrender libgomp libxcb \
            iputils traceroute nmap tcpdump
            
    elif command -v apk &> /dev/null; then
        # Alpine
        sudo apk add \
            python3 py3-pip \
            mesa-gl glib libx11 libxext \
            libxrender libxcb \
            iputils traceroute nmap tcpdump
    else
        echo "Unsupported Linux distribution"
        exit 1
    fi
}

# Function to install Mac dependencies
install_mac_deps() {
    echo "Installing Mac dependencies..."
    
    if ! command -v brew &> /dev/null; then
        echo "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    
    brew install python3
    brew install nmap
    brew install tcpdump
}

# Install OS-specific dependencies
case "${OS_TYPE}" in
    Linux)
        install_linux_deps
        ;;
    Mac)
        install_mac_deps
        ;;
    Windows)
        echo "Windows detected. Please ensure you have Python installed."
        echo "Download Python from: https://www.python.org/downloads/"
        echo "Also install Npcap from: https://npcap.com/"
        ;;
    *)
        echo "Unknown OS. Please install dependencies manually."
        exit 1
        ;;
esac

# Create Python virtual environment
echo "Creating Python virtual environment..."
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate || source venv/Scripts/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install Python requirements
echo "Installing Python requirements..."
pip install -r requirements.txt

# Create necessary directories
echo "Creating directories..."
mkdir -p data icons logs

# Setup complete
echo ""
echo "========================================="
echo "Setup Complete!"
echo "========================================="
echo ""
echo "To run CyberDrill:"
echo "  1. Activate virtual environment:"
echo "     source venv/bin/activate (Linux/Mac)"
echo "     venv\\Scripts\\activate (Windows)"
echo "  2. Run: python cyberdrill.py"
echo ""
echo "Or use the run script:"
echo "  ./run.sh (Linux/Mac)"
echo "  run.bat (Windows)"
echo ""