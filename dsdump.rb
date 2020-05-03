class dsdump < Formula
  desc "An improved nm + Objective-C & Swift class-dump"
  homepage "https://github.com/DerekSelander/dsdump"
  version "0.0.8-beta"
  sha256 "3c8811eef755596e4e71b1454b8ce27966c2117d02ad9fe52eafb385dce5b885"


  url "https://github.com/DerekSelander/dsdump/blob/master/compiled/dsdump.zip", :using => :curl


  def install
    bin.install "selander/dsdump"
  end
end
