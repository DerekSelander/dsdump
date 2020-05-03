class dsdump < Formula
  desc "An improved nm + Objective-C & Swift class-dump"
  homepage "https://github.com/DerekSelander/dsdump"
  version "0.0.8-beta"
  sha256 "c293418c10b5f501f38f96a6d498c775299d4df49792036dbd5ad00b6f6a0381"


  url "https://github.com/DerekSelander/dsdump/blob/master/compiled/dsdump.zip", :using => :curl


  def install
    bin.install "selander/dsdump"
  end
end
