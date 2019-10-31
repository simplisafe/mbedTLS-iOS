Pod::Spec.new do |s|

s.name         = "mbedTLS"
s.version      = "0.2.2"
s.summary      = "An iOS port of mbed TLS."

s.description  = <<-DESC
                  A Swift framework for working with SSL. Built on mbed TLS (https://tls.mbed.org/). 
                   DESC

s.homepage     = "https://github.com/simplisafe/mbedTLS-iOS"

s.license      = { :type => "MIT", :file => "LICENSE" }

s.author             = "Siddarth Gandhi"

s.ios.deployment_target = "10.0"

s.source       = { :git => "https://github.com/simplisafe/mbedTLS-iOS.git", :tag => "#{s.version}" }
s.source_files  = "mbedTLS/*.{swift,h}", "mbedTLS/mbedtls/*.{h,c}", "mbedTLS/Wrapper/*.{swift,c,h}"
s.public_header_files = "mbedTLS/*.h"
s.preserve_paths = "mbedTLS/mbedtls/module.modulemap"
s.requires_arc = true
s.xcconfig = { 'SWIFT_INCLUDE_PATHS' => '$(SRCROOT)/mbedTLS/mbedTLS/mbedtls/','LIBRARY_SEARCH_PATHS' => '$(SRCROOT)/mbedTLS/mbedTLS/' }

end
