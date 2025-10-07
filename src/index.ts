import { NativeModules, Platform } from "react-native";

const CSRGenerator = Platform.OS === "ios" ? NativeModules.CSRGeneratorModule : NativeModules.CSRGenerator;

export interface CSRParams {
  cn?: string;
  userId?: string;
  country?: string;
  state?: string;
  locality?: string;
  organization?: string;
  organizationalUnit?: string;
}

export interface CSRGeneratorInterface {
  generateECCKeyPair(): Promise;
  generateCSR(
    cn?: string,
    userId?: string,
    country?: string,
    state?: string,
    locality?: string,
    organization?: string,
    organizationalUnit?: string
  ): Promise;
}

if (!CSRGenerator) {
  throw new Error(
    'CSRGenerator native module is not available. Make sure the package is properly linked.'
  );
}
export default CSRGenerator as CSRGeneratorInterface;