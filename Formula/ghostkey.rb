class Ghostkey < Formula
  desc "Credential firewall for AI agents — agents send the ghost, servers get the key"
  homepage "https://github.com/yourusername/ghostkey"
  version "0.1.3"

  on_macos do
    on_arm do
      url "https://github.com/yourusername/ghostkey/releases/download/v0.1.3/ghostkey-darwin-arm64"
      sha256 "REPLACE_WITH_ACTUAL_SHA256"
    end
    on_intel do
      url "https://github.com/yourusername/ghostkey/releases/download/v0.1.3/ghostkey-darwin-amd64"
      sha256 "REPLACE_WITH_ACTUAL_SHA256"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/yourusername/ghostkey/releases/download/v0.1.3/ghostkey-linux-arm64"
      sha256 "REPLACE_WITH_ACTUAL_SHA256"
    end
    on_intel do
      url "https://github.com/yourusername/ghostkey/releases/download/v0.1.3/ghostkey-linux-amd64"
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
    puts "  1. Run: ghostkey ca install"
    puts "  2. Add your first credential: ghostkey vault add GHOST::mykey -"
    puts "  3. Start the proxy: ghostkey start"
    puts ""
  end

  test do
    system "#{bin}/ghostkey", "version"
  end
end
