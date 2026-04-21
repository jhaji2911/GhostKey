class Ghostkey < Formula
  desc "Credential firewall for AI agents — agents send the ghost, servers get the key"
  homepage "https://github.com/jhaji2911/GhostKey"
  version "0.1.4"

  on_macos do
    on_arm do
      url "https://github.com/jhaji2911/GhostKey/releases/download/v0.1.4/ghostkey-darwin-arm64"
      sha256 "REPLACE_WITH_ACTUAL_SHA256"
    end
    on_intel do
      url "https://github.com/jhaji2911/GhostKey/releases/download/v0.1.4/ghostkey-darwin-amd64"
      sha256 "REPLACE_WITH_ACTUAL_SHA256"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/jhaji2911/GhostKey/releases/download/v0.1.4/ghostkey-linux-arm64"
      sha256 "REPLACE_WITH_ACTUAL_SHA256"
    end
    on_intel do
      url "https://github.com/jhaji2911/GhostKey/releases/download/v0.1.4/ghostkey-linux-amd64"
      sha256 "REPLACE_WITH_ACTUAL_SHA256"
    end
  end

  def install
    arch = Hardware::CPU.arm? ? "arm64" : "amd64"
    platform = OS.mac? ? "darwin" : "linux"
    bin.install "ghostkey-#{platform}-#{arch}" => "ghostkey"
  end

  def post_install
    puts ""
    puts "  Next steps:"
    puts "  1. Add your first credential: ghostkey vault add GHOST::openai"
    puts "  2. Run your agent: ghostkey wrap -- python agent.py"
    puts "  3. Check everything: ghostkey doctor"
    puts ""
  end

  test do
    system "#{bin}/ghostkey", "version"
  end
end
