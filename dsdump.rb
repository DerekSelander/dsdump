class dsdump < Formula
  desc "An improved nm + Objective-C & Swift class-dump"
  homepage "https://github.com/DerekSelander/dsdump"
  version "0.0.10"
  sha256 "27190d5a69e3fbd6be35f511c13e70a5c06e6538cc116393d3fa8082fb0c12f5"


  url "https://github.com/DerekSelander/dsdump/blob/master/compiled/dsdump.zip", :using => :curl


  def install
    bin.install "selander/dsdump"
  end
end
