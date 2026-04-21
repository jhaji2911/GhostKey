class Ghostkey < Formula
  desc "Credential firewall for AI agents — agents send the ghost, servers get the key"
  homepage "https://github.com/jhaji2911/GhostKey"
  version "0.1.4"

  on_macos do
    on_arm do
      url "https://github.com/jhaji2911/GhostKey/releases/download/v0.1.4/ghostkey-darwin-arm64"
      sha256 "093df099b2f3a83e4d0ed4ca51aa05cbd1eb8c1a9a1048c34b0aa34549bf678d"
    end
    on_intel do
      url "https://github.com/jhaji2911/GhostKey/releases/download/v0.1.4/ghostkey-darwin-amd64"
      sha256 "b0a1451b5d5cf90c76450d28a6227e020b923d8b8d088d063deba174be884b35"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/jhaji2911/GhostKey/releases/download/v0.1.4/ghostkey-linux-arm64"
      sha256 "f362fc41ec257cece99a5fc9a614935366dff0369441f83b5b8eb71be63e59be"
    end
    on_intel do
      url "https://github.com/jhaji2911/GhostKey/releases/download/v0.1.4/ghostkey-linux-amd64"
      sha256 "bb01365469df7e946e09e164d7a1f4d3711390914fd14df8ac69c7e965c0621d"
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
