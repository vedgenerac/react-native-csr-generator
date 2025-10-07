import { NativeModules } from "react-native";

const { CSRGenerator } = NativeModules;

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

export default CSRGenerator as CSRGeneratorInterface;