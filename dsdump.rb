class dsdump < Formula
  desc "An improved nm + Objective-C & Swift class-dump"
  homepage "https://github.com/DerekSelander/dsdump"
  version "0.0.9"
  sha256 "dbff451c4e097c1aafbebf9db667ed3a2bebdd23ad2b44f9e5724400943d5f01"


  url "https://github.com/DerekSelander/dsdump/blob/master/compiled/dsdump.zip", :using => :curl


  def install
    bin.install "selander/dsdump"
  end
end
