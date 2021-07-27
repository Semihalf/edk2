DefinitionBlock ("SsdtSerialPortTemplate.aml", "SSDT", 2, "ARMLTD", "SERIAL", 1) {
  Scope (_SB) {
    Device (COM0) {                    // {template}
      Name (_UID, Zero)                // {template} Unique ID
      Name (_HID, "MRVL0001")          // {template} Hardware ID
      Name (_CID, "HISI0031")          // {template} Compatible ID

      Method (_STA, 0, NotSerialized)  // _STA: Status
      {
	  Return (0x0F)
      }

      Name (_ADR, 0xF0512000)          // _ADR: Address
      Name (_CRS, ResourceTemplate ()  // _CRS: Current Resource Settings
      {
	  Memory32Fixed (ReadWrite,
	      0xF0512000,              // Address Base
	      0x00000100,              // Address Length
	      )
	  Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive, ,, )
	  {
	      0x00000033,              //  // {template}
	  }
      })
      Name (_DSD, Package (0x02)       // _DSD: Device-Specific Data
      {
	ToUUID ("daffd814-6eba-4d8c-8a91-bc9bbf4aa301") /* Device Properties for _DSD */, 
	Package (0x03)
	{
	  Package (0x02)
	  {
	    "clock-frequency", 
	    0x0BEBC200
	  }, 

	  Package (0x02)
	  {
	    "reg-io-width", 
	    One
	  }, 

	  Package (0x02)
	  {
	    "reg-shift", 
	     0x02
	  }
	}
      })
    } // Device
  } // Scope
}
