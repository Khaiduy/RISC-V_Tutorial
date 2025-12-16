package chipyard

import org.chipsalliance.cde.config.{Config}
import freechips.rocketchip.diplomacy.{AsynchronousCrossing}

// --------------
// Rocket+SHA3 Configs
// These live in a separate file to simplify patching out for the tutorials.
// --------------

// DOC include start: Sha3Rocket
class Sha3RocketConfig extends Config(
  //new sha3.WithSha3Accel ++                                // add SHA3 rocc accelerator
  new chipyard.iobinders.WithDontTouchIOBinders(false) ++              // TODO: hack around dontTouch not working in SFC
  new chipyard.example.WithGCD(useAXI4=false, useBlackBox=false) ++          // Use GCD Chisel, connect Tilelink
  //new fftgenerator.WithFFTGenerator(numPoints=8, width=16, decPt=8) ++ // add 8-point mmio fft at the default addr (0x2400) with 16bit fixed-point numbers.
  new freechips.rocketchip.subsystem.WithNSmallCores(1) ++
  new chipyard.config.AbstractConfig)
// DOC include end: Sha3Rocket

class Sha3RocketPrintfConfig extends Config(
  new sha3.WithSha3Printf ++
  new sha3.WithSha3Accel ++                                // add SHA3 rocc accelerator
  new freechips.rocketchip.subsystem.WithNBigCores(1) ++
  new chipyard.config.AbstractConfig)
