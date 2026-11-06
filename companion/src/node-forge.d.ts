// Minimal ambient declarations for the part of node-forge the companion uses (#2315): opening a
// PKCS#12 (PFX) file in memory to hand its key and certificate to Node's own crypto. Declared here
// rather than adding @types/node-forge as a second dependency; widen it only as far as a new use
// needs.
declare module "node-forge" {
  export namespace asn1 {
    interface Asn1 {
      tagClass: number;
      type: number;
      constructed: boolean;
      value: unknown;
    }
    function fromDer(bytes: string): Asn1;
    function toDer(obj: Asn1): { getBytes(): string };
  }
  export namespace pki {
    namespace rsa {
      interface PrivateKey {
        n: unknown;
      }
    }
    interface Certificate {
      serialNumber: string;
    }
    const oids: Record<string, string>;
    function privateKeyToAsn1(key: rsa.PrivateKey): asn1.Asn1;
    function wrapRsaPrivateKey(rsaKey: asn1.Asn1): asn1.Asn1;
    function certificateToAsn1(cert: Certificate): asn1.Asn1;
    function privateKeyFromPem(pem: string): rsa.PrivateKey;
    function certificateFromPem(pem: string): Certificate;
  }
  export namespace pkcs12 {
    interface Bag {
      key?: pki.rsa.PrivateKey | null;
      cert?: pki.Certificate | null;
      asn1?: asn1.Asn1;
    }
    interface Pkcs12Pfx {
      getBags(filter: { bagType: string }): Record<string, Bag[] | undefined>;
    }
    function pkcs12FromAsn1(obj: asn1.Asn1, password: string): Pkcs12Pfx;
    function toPkcs12Asn1(
      key: pki.rsa.PrivateKey,
      cert: pki.Certificate | pki.Certificate[],
      password: string,
      options?: { algorithm?: "aes128" | "aes192" | "aes256" | "3des" },
    ): asn1.Asn1;
  }
  const forge: { asn1: typeof asn1; pki: typeof pki; pkcs12: typeof pkcs12 };
  export default forge;
}
