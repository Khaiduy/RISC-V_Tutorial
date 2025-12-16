package chipyard.crypto.aes_gcm

object AES_GCMRegs {
  val ICTRL = 0x100
  val OREADY = 0x108

  val IIV_0 = 0x110
  val IIV_1 = 0x118
  val IIV_VALID = 0x120

  val IKEY_0 = 0x128
  val IKEY_1 = 0x130
  val IKEY_2 = 0x138
  val IKEY_3 = 0x140
  val IKEY_VALID = 0x148
  val IKEYLEN = 0x150

  val IAAD_0 = 0x158
  val IAAD_1 = 0x160
  val IAAD_VALID = 0x168

  val IBLOCK_0 = 0x170
  val IBLOCK_1 = 0x178
  val IBLOCK_VALID = 0x180

  val ITAG_0 = 0x188
  val ITAG_1 = 0x190
  val ITAG_VALID = 0x198

  val ORESULT_0 = 0x1A0
  val ORESULT_1 = 0x1A8
  val ORESULT_VALID = 0x1B0

  val OTAG_0 = 0x1B8
  val OTAG_1 = 0x1C0
  val OTAG_VALID = 0x1C8

  val OAUTHENTIC = 0x1D0
  val IRESETN = 0x1D8

  val IBLOCK_BYTES = 0x1E0
}