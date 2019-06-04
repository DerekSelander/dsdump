file(REMOVE_RECURSE
  "AMDGPUGenAsmMatcher.inc"
  "AMDGPUGenAsmWriter.inc"
  "AMDGPUGenCallingConv.inc"
  "AMDGPUGenDAGISel.inc"
  "AMDGPUGenDisassemblerTables.inc"
  "AMDGPUGenInstrInfo.inc"
  "AMDGPUGenMCCodeEmitter.inc"
  "AMDGPUGenMCPseudoLowering.inc"
  "AMDGPUGenRegisterBank.inc"
  "AMDGPUGenRegisterInfo.inc"
  "AMDGPUGenSearchableTables.inc"
  "AMDGPUGenSubtargetInfo.inc"
  "AMDGPUGenGlobalISel.inc"
  "R600GenAsmWriter.inc"
  "R600GenCallingConv.inc"
  "R600GenDAGISel.inc"
  "R600GenDFAPacketizer.inc"
  "R600GenInstrInfo.inc"
  "R600GenMCCodeEmitter.inc"
  "R600GenRegisterInfo.inc"
  "R600GenSubtargetInfo.inc"
  "CMakeFiles/install-LLVMAMDGPUCodeGen"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/install-LLVMAMDGPUCodeGen.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
