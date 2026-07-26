#!/usr/bin/env bash
set -euo pipefail

exec > >(tee /var/log/graceful-gut-bootstrap.log | logger -t graceful-gut-bootstrap -s 2>/dev/console) 2>&1

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y \
  ca-certificates \
  curl \
  git \
  jq \
  nodejs \
  npm \
  python3 \
  python3-pip \
  python3-venv \
  ripgrep \
  unzip

if ! id claude >/dev/null 2>&1; then
    useradd --create-home --shell /bin/bash claude
fi

mkdir -p /home/claude/projects
mkdir -p /home/claude/.npm-global
chown -R claude:claude /home/claude

sudo -u claude -H npm config set prefix /home/claude/.npm-global

if ! grep -q '.npm-global/bin' /home/claude/.profile; then
    echo 'export PATH="$HOME/.npm-global/bin:$PATH"' >> /home/claude/.profile
fi

sudo -u claude -H env \
  PATH="/home/claude/.npm-global/bin:/usr/bin:/bin" \
  npm install -g @anthropic-ai/claude-code

curl -fsSLo /tmp/awscliv2.zip \
  https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip

rm -rf /tmp/aws
unzip -q /tmp/awscliv2.zip -d /tmp
/tmp/aws/install --update

if command -v snap >/dev/null 2>&1; then
    if ! snap list amazon-ssm-agent >/dev/null 2>&1; then
        snap install amazon-ssm-agent --classic
    fi

    systemctl enable --now snap.amazon-ssm-agent.amazon-ssm-agent.service || true
fi

sudo -u claude -H bash -lc '
  {
    echo "Node: $(node --version)"
    echo "NPM: $(npm --version)"
    echo "Claude: $(claude --version)"
    echo "Git: $(git --version)"
    echo "Python: $(python3 --version)"
    echo "AWS: $(aws --version 2>&1)"
  } > "$HOME/bootstrap-versions.txt"
'

touch /var/lib/graceful-gut-bootstrap-complete
