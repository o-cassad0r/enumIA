#!/bin/bash

# Subfinder (ProjectDiscovery)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Assetfinder (Tomnomnom)
go get -u github.com/tomnomnom/assetfinder

# Amass (OWASP)
sudo apt install amass -y

# DNSx (ProjectDiscovery)
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Httpx (ProjectDiscovery)
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Go binaries path (se necessário)
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc
