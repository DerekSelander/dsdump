class dsdump < Formula
  desc "An improved nm + Objective-C & Swift class-dump"
  homepage "https://github.com/DerekSelander/dsdump"
  version "0.0.8-beta"


  url "https://github.com/DerekSelander/dsdump/archive/beta_8.zip", :using => :curl

  def install
    bin.install "selander/dsdump"
  end
end
