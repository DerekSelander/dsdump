class dsdump < Formula
  desc "An improved nm + Objective-C & Swift class-dump"
  homepage "https://github.com/DerekSelander/dsdump"
  version "0.1.0"
  sha256 "83eebd025b43b58a486235e1bec70a3239995be409605e3ff19bdae07adff917"


  url "https://github.com/DerekSelander/dsdump/blob/master/compiled/dsdump.zip", :using => :curl


  def install
    bin.install "selander/dsdump"
  end
end
