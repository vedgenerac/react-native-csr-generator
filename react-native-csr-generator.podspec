require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "react-native-csr-generator"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]

  s.platforms    = { :ios => "13.0" }
  s.source       = { :git => "https://github.com/vedgenerac/react-native-csr-generator.git", :tag => "#{s.version}" }

  s.source_files = "ios/**/*.{h,m,mm,swift,c}"
  s.module_map   = "ios/module.modulemap"

  s.dependency "React-Core"
  s.dependency "OpenSSL-Universal", "~> 1.1.1"
  
  # Build as a framework instead of static library
  s.static_framework = true
  
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'SWIFT_VERSION' => '5.0',
    'HEADER_SEARCH_PATHS' => '$(PODS_TARGET_SRCROOT)/ios'
  }
end