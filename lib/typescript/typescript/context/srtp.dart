class SrtpContext {
  Profile? srtpProfile;

  static Profile? findMatchingSRTPProfile(
      List<Profile> remote, List<Profile> local) {
    for (final v in local) {
      if (remote.contains(v)) return v;
    }
    return null;
  }
}

const int ProtectionProfileAes128CmHmacSha1_80 = 0x0001;
const int ProtectionProfileAeadAes128Gcm = 0x0007;

const List<int> Profiles = [
  ProtectionProfileAes128CmHmacSha1_80,
  ProtectionProfileAeadAes128Gcm,
];

typedef Profile = int;
