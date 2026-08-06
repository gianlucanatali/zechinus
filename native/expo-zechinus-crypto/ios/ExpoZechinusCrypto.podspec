Pod::Spec.new do |s|
  s.name           = 'ExpoZechinusCrypto'
  s.version        = '1.0.0'
  s.summary        = 'Native AEAD/HKDF/HMAC primitives with in-native-memory key isolation for zechinus'
  s.description    = 'Per-instance native key handles (CryptoKit on iOS) mirroring the isolation a Web Worker gives zechinus on web — the key material never crosses into JS.'
  s.author         = ''
  s.homepage       = 'https://github.com/gianlucanatali/zechinus'
  s.platforms      = {
    :ios => '16.4',
    :tvos => '16.4'
  }
  s.source         = { git: '' }
  s.static_framework = true

  s.dependency 'ExpoModulesCore'

  # Swift/Objective-C compatibility
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
  }

  s.source_files = "**/*.{h,m,mm,swift,hpp,cpp}"
  s.exclude_files = "**/*Tests.swift"

  s.test_spec 'Tests' do |test_spec|
    test_spec.source_files = "**/*Tests.swift"
  end
end
