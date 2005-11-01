/*******************************************************************************
 *
 * Module Name: dmresrcl.c - "Large" Resource Descriptor disassembly
 *              $Revision: 1.29 $
 *
 ******************************************************************************/

/******************************************************************************
 *
 * 1. Copyright Notice
 *
 * Some or all of this work - Copyright (c) 1999 - 2005, Intel Corp.
 * All rights reserved.
 *
 * 2. License
 *
 * 2.1. This is your license from Intel Corp. under its intellectual property
 * rights.  You may have additional license terms from the party that provided
 * you this software, covering your right to use that party's intellectual
 * property rights.
 *
 * 2.2. Intel grants, free of charge, to any person ("Licensee") obtaining a
 * copy of the source code appearing in this file ("Covered Code") an
 * irrevocable, perpetual, worldwide license under Intel's copyrights in the
 * base code distributed originally by Intel ("Original Intel Code") to copy,
 * make derivatives, distribute, use and display any portion of the Covered
 * Code in any form, with the right to sublicense such rights; and
 *
 * 2.3. Intel grants Licensee a non-exclusive and non-transferable patent
 * license (with the right to sublicense), under only those claims of Intel
 * patents that are infringed by the Original Intel Code, to make, use, sell,
 * offer to sell, and import the Covered Code and derivative works thereof
 * solely to the minimum extent necessary to exercise the above copyright
 * license, and in no event shall the patent license extend to any additions
 * to or modifications of the Original Intel Code.  No other license or right
 * is granted directly or by implication, estoppel or otherwise;
 *
 * The above copyright and patent license is granted only if the following
 * conditions are met:
 *
 * 3. Conditions
 *
 * 3.1. Redistribution of Source with Rights to Further Distribute Source.
 * Redistribution of source code of any substantial portion of the Covered
 * Code or modification with rights to further distribute source must include
 * the above Copyright Notice, the above License, this list of Conditions,
 * and the following Disclaimer and Export Compliance provision.  In addition,
 * Licensee must cause all Covered Code to which Licensee contributes to
 * contain a file documenting the changes Licensee made to create that Covered
 * Code and the date of any change.  Licensee must include in that file the
 * documentation of any changes made by any predecessor Licensee.  Licensee
 * must include a prominent statement that the modification is derived,
 * directly or indirectly, from Original Intel Code.
 *
 * 3.2. Redistribution of Source with no Rights to Further Distribute Source.
 * Redistribution of source code of any substantial portion of the Covered
 * Code or modification without rights to further distribute source must
 * include the following Disclaimer and Export Compliance provision in the
 * documentation and/or other materials provided with distribution.  In
 * addition, Licensee may not authorize further sublicense of source of any
 * portion of the Covered Code, and must include terms to the effect that the
 * license from Licensee to its licensee is limited to the intellectual
 * property embodied in the software Licensee provides to its licensee, and
 * not to intellectual property embodied in modifications its licensee may
 * make.
 *
 * 3.3. Redistribution of Executable. Redistribution in executable form of any
 * substantial portion of the Covered Code or modification must reproduce the
 * above Copyright Notice, and the following Disclaimer and Export Compliance
 * provision in the documentation and/or other materials provided with the
 * distribution.
 *
 * 3.4. Intel retains all right, title, and interest in and to the Original
 * Intel Code.
 *
 * 3.5. Neither the name Intel nor any other trademark owned or controlled by
 * Intel shall be used in advertising or otherwise to promote the sale, use or
 * other dealings in products derived from or relating to the Covered Code
 * without prior written authorization from Intel.
 *
 * 4. Disclaimer and Export Compliance
 *
 * 4.1. INTEL MAKES NO WARRANTY OF ANY KIND REGARDING ANY SOFTWARE PROVIDED
 * HERE.  ANY SOFTWARE ORIGINATING FROM INTEL OR DERIVED FROM INTEL SOFTWARE
 * IS PROVIDED "AS IS," AND INTEL WILL NOT PROVIDE ANY SUPPORT,  ASSISTANCE,
 * INSTALLATION, TRAINING OR OTHER SERVICES.  INTEL WILL NOT PROVIDE ANY
 * UPDATES, ENHANCEMENTS OR EXTENSIONS.  INTEL SPECIFICALLY DISCLAIMS ANY
 * IMPLIED WARRANTIES OF MERCHANTABILITY, NONINFRINGEMENT AND FITNESS FOR A
 * PARTICULAR PURPOSE.
 *
 * 4.2. IN NO EVENT SHALL INTEL HAVE ANY LIABILITY TO LICENSEE, ITS LICENSEES
 * OR ANY OTHER THIRD PARTY, FOR ANY LOST PROFITS, LOST DATA, LOSS OF USE OR
 * COSTS OF PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES, OR FOR ANY INDIRECT,
 * SPECIAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THIS AGREEMENT, UNDER ANY
 * CAUSE OF ACTION OR THEORY OF LIABILITY, AND IRRESPECTIVE OF WHETHER INTEL
 * HAS ADVANCE NOTICE OF THE POSSIBILITY OF SUCH DAMAGES.  THESE LIMITATIONS
 * SHALL APPLY NOTWITHSTANDING THE FAILURE OF THE ESSENTIAL PURPOSE OF ANY
 * LIMITED REMEDY.
 *
 * 4.3. Licensee shall not export, either directly or indirectly, any of this
 * software or system incorporating such software without first obtaining any
 * required license or other approval from the U. S. Department of Commerce or
 * any other agency or department of the United States Government.  In the
 * event Licensee exports any such software from the United States or
 * re-exports any such software from a foreign destination, Licensee shall
 * ensure that the distribution and export/re-export of the software is in
 * compliance with all laws, regulations, orders, or other restrictions of the
 * U.S. Export Administration Regulations. Licensee agrees that neither it nor
 * any of its subsidiaries will export/re-export any technical data, process,
 * software, or service, directly or indirectly, to any country for which the
 * United States government or any agency thereof requires an export license,
 * other governmental approval, or letter of assurance, without first obtaining
 * such license, approval or letter.
 *
 *****************************************************************************/


#include <contrib/dev/acpica/acpi.h>
#include <contrib/dev/acpica/acdisasm.h>


#ifdef ACPI_DISASSEMBLER

#define _COMPONENT          ACPI_CA_DEBUGGER
        ACPI_MODULE_NAME    ("dbresrcl")


/* Common names for address and memory descriptors */

static char                 *AcpiDmAddressNames[] =
{
    "Address Space Granularity",
    "Address Range Minimum",
    "Address Range Maximum",
    "Address Translation Offset",
    "Address Length"
};

static char                 *AcpiDmMemoryNames[] =
{
    "Address Range Minimum",
    "Address Range Maximum",
    "Address Alignment",
    "Address Length"
};


/* Local prototypes */

static void
AcpiDmSpaceFlags (
        UINT8               Flags);

static void
AcpiDmIoFlags (
        UINT8               Flags);

static void
AcpiDmIoFlags2 (
        UINT8               SpecificFlags);

static void
AcpiDmMemoryFlags (
    UINT8                   Flags,
    UINT8                   SpecificFlags);

static void
AcpiDmMemoryFlags2 (
    UINT8                   SpecificFlags);

static void
AcpiDmResourceSource (
    AML_RESOURCE            *Resource,
    ACPI_SIZE               MinimumLength,
    UINT32                  Length);

static void
AcpiDmAddressFields (
    void                    *Source,
    UINT8                   Type,
    UINT32                  Level);

static void
AcpiDmAddressPrefix (
    UINT8                   Type);

static void
AcpiDmAddressCommon (
    AML_RESOURCE            *Resource,
    UINT8                   Type,
    UINT32                  Level);

static void
AcpiDmAddressFlags (
    AML_RESOURCE            *Resource);


/*******************************************************************************
 *
 * FUNCTION:    AcpiDmMemoryFields
 *
 * PARAMETERS:  Source              - Pointer to the contiguous data fields
 *              Type                - 16 or 32 (bit)
 *              Level               - Current source code indentation level
 *
 * RETURN:      None
 *
 * DESCRIPTION: Decode fields common to Memory24 and Memory32 descriptors
 *
 ******************************************************************************/

static void
AcpiDmMemoryFields (
    void                    *Source,
    UINT8                   Type,
    UINT32                  Level)
{
    ACPI_NATIVE_UINT        i;


    for (i = 0; i < 4; i++)
    {
        AcpiDmIndent (Level + 1);

        switch (Type)
        {
        case 16:
            AcpiDmDumpInteger16 (((UINT16 *) Source)[i], AcpiDmMemoryNames[i]);
            break;

        case 32:
            AcpiDmDumpInteger32 (((UINT32 *) Source)[i], AcpiDmMemoryNames[i]);
            break;

        default:
            return;
        }
    }
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiDm
 *
 * PARAMETERS:  Source              - Pointer to the contiguous data fields
 *              Type                - 16, 32, or 64 (bit)
 *              Level               - Current source code indentation level
 *
 * RETURN:      None
 *
 * DESCRIPTION: Decode fields common to address descriptors
 *
 ******************************************************************************/

static void
AcpiDmAddressFields (
    void                    *Source,
    UINT8                   Type,
    UINT32                  Level)
{
    ACPI_NATIVE_UINT        i;


    AcpiOsPrintf ("\n");

    for (i = 0; i < 5; i++)
    {
        AcpiDmIndent (Level + 1);

        switch (Type)
        {
        case 16:
            AcpiDmDumpInteger16 (((UINT16 *) Source)[i], AcpiDmAddressNames[i]);
            break;

        case 32:
            AcpiDmDumpInteger32 (((UINT32 *) Source)[i], AcpiDmAddressNames[i]);
            break;

        case 64:
            AcpiDmDumpInteger64 (((UINT64 *) Source)[i], AcpiDmAddressNames[i]);
            break;

        default:
            return;
        }
    }
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiDmAddressPrefix
 *
 * PARAMETERS:  Type                - Descriptor type
 *
 * RETURN:      None
 *
 * DESCRIPTION: Emit name prefix representing the address descriptor type
 *
 ******************************************************************************/

static void
AcpiDmAddressPrefix (
    UINT8                   Type)
{

    switch (Type)
    {
    case ACPI_RESOURCE_TYPE_ADDRESS16:
        AcpiOsPrintf ("Word");
        break;

    case ACPI_RESOURCE_TYPE_ADDRESS32:
        AcpiOsPrintf ("DWord");
        break;

    case ACPI_RESOURCE_TYPE_ADDRESS64:
        AcpiOsPrintf ("QWord");
        break;

    case ACPI_RESOURCE_TYPE_EXTENDED_ADDRESS64:
        AcpiOsPrintf ("Extended");
        break;

    default:
        return;
    }
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiDmAddressCommon
 *
 * PARAMETERS:  Resource            - Raw AML descriptor
 *              Type                - Descriptor type
 *              Level               - Current source code indentation level
 *
 * RETURN:      None
 *
 * DESCRIPTION: Emit common name and flag fields common to address descriptors
 *
 ******************************************************************************/

static void
AcpiDmAddressCommon (
    AML_RESOURCE            *Resource,
    UINT8                   Type,
    UINT32                  Level)
{
    UINT8                   ResourceType;
    UINT8                   SpecificFlags;
    UINT8                   Flags;


    ResourceType = Resource->Address.ResourceType;
    SpecificFlags = Resource->Address.SpecificFlags;
    Flags = Resource->Address.Flags;

    AcpiDmIndent (Level);

    /* Validate ResourceType */

    if ((ResourceType > 2) && (ResourceType < 0xC0))
    {
        AcpiOsPrintf ("/**** Invalid Resource Type: 0x%X ****/", ResourceType);
        return;
    }

    /* Prefix is either Word, DWord, QWord, or Extended */

    AcpiDmAddressPrefix (Type);

    /* Resource Types above 0xC0 are vendor-defined */

    if (ResourceType > 2)
    {
        AcpiOsPrintf ("Space (0x%2.2X, ", ResourceType);
        AcpiDmSpaceFlags (Flags);
        AcpiOsPrintf (" 0x%2.2X,", SpecificFlags);
        return;
    }

    /* This is either a Memory, IO, or BusNumber descriptor (0,1,2) */

    AcpiOsPrintf ("%s (", AcpiGbl_WordDecode [ResourceType]);

    /* Decode the general and type-specific flags */

    if (ResourceType == ACPI_MEMORY_RANGE)
    {
        AcpiDmMemoryFlags (Flags, SpecificFlags);
    }
    else /* IO range or BusNumberRange */
    {
        AcpiDmIoFlags (Flags);
        if (ResourceType == ACPI_IO_RANGE)
        {
            AcpiOsPrintf (" %s,", AcpiGbl_RNGDecode [SpecificFlags & 0x3]);
        }
    }
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiDmAddressFlags
 *
 * PARAMETERS:  Resource        - Raw AML descriptor
 *
 * RETURN:      None
 *
 * DESCRIPTION: Emit flags common to address descriptors
 *
 ******************************************************************************/

static void
AcpiDmAddressFlags (
    AML_RESOURCE            *Resource)
{

    if (Resource->Address.ResourceType == ACPI_IO_RANGE)
    {
        AcpiDmIoFlags2 (Resource->Address.SpecificFlags);
    }
    else if (Resource->Address.ResourceType == ACPI_MEMORY_RANGE)
    {
        AcpiDmMemoryFlags2 (Resource->Address.SpecificFlags);
    }
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiDmSpaceFlags
 *
 * PARAMETERS:  Flags               - Flag byte to be decoded
 *
 * RETURN:      None
 *
 * DESCRIPTION: Decode the flags specific to Space Address space descriptors
 *
 ******************************************************************************/

static void
AcpiDmSpaceFlags (
    UINT8                   Flags)
{

    AcpiOsPrintf ("%s, %s, %s, %s,",
        AcpiGbl_ConsumeDecode [(Flags & 1)],
        AcpiGbl_DECDecode [(Flags & 0x2) >> 1],
        AcpiGbl_MinDecode [(Flags & 0x4) >> 2],
        AcpiGbl_MaxDecode [(Flags & 0x8) >> 3]);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiDmIoFlags
 *
 * PARAMETERS:  Flags               - Flag byte to be decoded
 *
 * RETURN:      None
 *
 * DESCRIPTION: Decode the flags specific to IO Address space descriptors
 *
 ******************************************************************************/

static void
AcpiDmIoFlags (
        UINT8               Flags)
{
    AcpiOsPrintf ("%s, %s, %s, %s,",
        AcpiGbl_ConsumeDecode [(Flags & 1)],
        AcpiGbl_MinDecode [(Flags & 0x4) >> 2],
        AcpiGbl_MaxDecode [(Flags & 0x8) >> 3],
        AcpiGbl_DECDecode [(Flags & 0x2) >> 1]);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiDmIoFlags2
 *
 * PARAMETERS:  SpecificFlags       - "Specific" flag byte to be decoded
 *
 * RETURN:      None
 *
 * DESCRIPTION: Decode the flags specific to IO Address space descriptors
 *
 ******************************************************************************/

static void
AcpiDmIoFlags2 (
        UINT8               SpecificFlags)
{

    AcpiOsPrintf (", %s",
        AcpiGbl_TTPDecode [(SpecificFlags & 0x10) >> 4]);

    /* TRS is only used if TTP is TypeTranslation */

    if (SpecificFlags & 0x10)
    {
        AcpiOsPrintf (", %s",
            AcpiGbl_TRSDecode [(SpecificFlags & 0x20) >> 5]);
    }
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiDmMemoryFlags
 *
 * PARAMETERS:  Flags               - Flag byte to be decoded
 *              SpecificFlags       - "Specific" flag byte to be decoded
 *
 * RETURN:      None
 *
 * DESCRIPTION: Decode flags specific to Memory Address Space descriptors
 *
 ******************************************************************************/

static void
AcpiDmMemoryFlags (
    UINT8                   Flags,
    UINT8                   SpecificFlags)
{

    AcpiOsPrintf ("%s, %s, %s, %s, %s, %s,",
        AcpiGbl_ConsumeDecode [(Flags & 1)],
        AcpiGbl_DECDecode [(Flags & 0x2) >> 1],
        AcpiGbl_MinDecode [(Flags & 0x4) >> 2],
        AcpiGbl_MaxDecode [(Flags & 0x8) >> 3],
        AcpiGbl_MEMDecode [(SpecificFlags & 0x6) >> 1],
        AcpiGbl_RWDecode [(SpecificFlags & 0x1)]);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiDmMemoryFlags2
 *
 * PARAMETERS:  SpecificFlags       - "Specific" flag byte to be decoded
 *
 * RETURN:      None
 *
 * DESCRIPTION: Decode flags specific to Memory Address Space descriptors
 *
 ******************************************************************************/

static void
AcpiDmMemoryFlags2 (
    UINT8                   SpecificFlags)
{

    AcpiOsPrintf (", %s, %s",
        AcpiGbl_MTPDecode [(SpecificFlags & 0x18) >> 3],
        AcpiGbl_TTPDecode [(SpecificFlags & 0x20) >> 5]);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiDmResourceSource
 *
 * PARAMETERS:  Resource        - Raw AML descriptor
 *              MinimumLength   - descriptor length without optional fields
 *              ResourceLength
 *
 * RETURN:      None
 *
 * DESCRIPTION: Dump optional ResourceSource fields of an address descriptor
 *
 ******************************************************************************/

static void
AcpiDmResourceSource (
    AML_RESOURCE            *Resource,
    ACPI_SIZE               MinimumTotalLength,
    UINT32                  ResourceLength)
{
    UINT8                   *AmlResourceSource;
    UINT32                  TotalLength;


    TotalLength = ResourceLength + sizeof (AML_RESOURCE_LARGE_HEADER);

    /* Check if the optional ResourceSource fields are present */

    if (TotalLength <= MinimumTotalLength)
    {
        /* The two optional fields are not used */

        AcpiOsPrintf (",,");
        return;
    }

    /* Get a pointer to the ResourceSource */

    AmlResourceSource = ((UINT8 *) Resource) + MinimumTotalLength;

    /*
     * Always emit the ResourceSourceIndex (Byte)
     *
     * NOTE: Some ASL compilers always create a 0 byte (in the AML) for the
     * Index even if the String does not exist. Although this is in violation
     * of the ACPI specification, it is very important to emit ASL code that
     * can be compiled back to the identical AML. There may be fields and/or
     * indexes into the resource template buffer that are compiled to absolute
     * offsets, and these will be broken if the AML length is changed.
     */
    AcpiOsPrintf ("0x%2.2X,", (UINT32) AmlResourceSource[0]);

    /* Make sure that the ResourceSource string exists before dumping it */

    if (TotalLength > (MinimumTotalLength + 1))
    {
        AcpiOsPrintf (" ");
        AcpiUtPrintString ((char *) &AmlResourceSource[1], ACPI_UINT8_MAX);
    }

    AcpiOsPrintf (",");
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiDmWordDescriptor
 *
 * PARAMETERS:  Resource            - Pointer to the resource descriptor
 *              Length              - Length of the descriptor in bytes
 *              Level               - Current source code indentation level
 *
 * RETURN:      None
 *
 * DESCRIPTION: Decode a Word Address Space descriptor
 *
 ******************************************************************************/

void
AcpiDmWordDescriptor (
    AML_RESOURCE            *Resource,
    UINT32                  Length,
    UINT32                  Level)
{

    /* Dump resource name and flags */

    AcpiDmAddressCommon (Resource, ACPI_RESOURCE_TYPE_ADDRESS16, Level);

    /* Dump the 5 contiguous WORD values */

    AcpiDmAddressFields (&Resource->Address16.Granularity, 16, Level);

    /* The ResourceSource fields are optional */

    AcpiDmIndent (Level + 1);
    AcpiDmResourceSource (Resource, sizeof (AML_RESOURCE_ADDRESS16), Length);

    /* Type-specific flags */

    AcpiDmAddressFlags (Resource);
    AcpiOsPrintf (")\n");
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiDmDwordDescriptor
 *
 * PARAMETERS:  Resource            - Pointer to the resource descriptor
 *              Length              - Length of the descriptor in bytes
 *              Level               - Current source code indentation level
 *
 * RETURN:      None
 *
 * DESCRIPTION: Decode a DWord Address Space descriptor
 *
 ******************************************************************************/

void
AcpiDmDwordDescriptor (
    AML_RESOURCE            *Resource,
    UINT32                  Length,
    UINT32                  Level)
{

    /* Dump resource name and flags */

    AcpiDmAddressCommon (Resource, ACPI_RESOURCE_TYPE_ADDRESS32, Level);

    /* Dump the 5 contiguous DWORD values */

    AcpiDmAddressFields (&Resource->Address32.Granularity, 32, Level);

    /* The ResourceSource fields are optional */

    AcpiDmIndent (Level + 1);
    AcpiDmResourceSource (Resource, sizeof (AML_RESOURCE_ADDRESS32), Length);

    /* Type-specific flags */

    AcpiDmAddressFlags (Resource);
    AcpiOsPrintf (")\n");
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiDmQwordDescriptor
 *
 * PARAMETERS:  Resource            - Pointer to the resource descriptor
 *              Length              - Length of the descriptor in bytes
 *              Level               - Current source code indentation level
 *
 * RETURN:      None
 *
 * DESCRIPTION: Decode a QWord Address Space descriptor
 *
 ******************************************************************************/

void
AcpiDmQwordDescriptor (
    AML_RESOURCE            *Resource,
    UINT32                  Length,
    UINT32                  Level)
{

    /* Dump resource name and flags */

    AcpiDmAddressCommon (Resource, ACPI_RESOURCE_TYPE_ADDRESS64, Level);

    /* Dump the 5 contiguous QWORD values */

    AcpiDmAddressFields (&Resource->Address64.Granularity, 64, Level);

    /* The ResourceSource fields are optional */

    AcpiDmIndent (Level + 1);
    AcpiDmResourceSource (Resource, sizeof (AML_RESOURCE_ADDRESS64), Length);

    /* Type-specific flags */

    AcpiDmAddressFlags (Resource);
    AcpiOsPrintf (")\n");
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiDmExtendedDescriptor
 *
 * PARAMETERS:  Resource            - Pointer to the resource descriptor
 *              Length              - Length of the descriptor in bytes
 *              Level               - Current source code indentation level
 *
 * RETURN:      None
 *
 * DESCRIPTION: Decode a Extended Address Space descriptor
 *
 ******************************************************************************/

void
AcpiDmExtendedDescriptor (
    AML_RESOURCE            *Resource,
    UINT32                  Length,
    UINT32                  Level)
{

    /* Dump resource name and flags */

    AcpiDmAddressCommon (Resource, ACPI_RESOURCE_TYPE_EXTENDED_ADDRESS64, Level);

    /* Dump the 5 contiguous QWORD values */

    AcpiDmAddressFields (&Resource->ExtAddress64.Granularity, 64, Level);

    /* Extra field for this descriptor only */

    AcpiDmIndent (Level + 1);
    AcpiDmDumpInteger64 (Resource->ExtAddress64.TypeSpecific,
        "Type-Specific Attributes");

    /* Type-specific flags */

    AcpiDmIndent (Level + 1);
    AcpiDmAddressFlags (Resource);
    AcpiOsPrintf (")\n");
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiDmMemory24Descriptor
 *
 * PARAMETERS:  Resource            - Pointer to the resource descriptor
 *              Length              - Length of the descriptor in bytes
 *              Level               - Current source code indentation level
 *
 * RETURN:      None
 *
 * DESCRIPTION: Decode a Memory24 descriptor
 *
 ******************************************************************************/

void
AcpiDmMemory24Descriptor (
    AML_RESOURCE            *Resource,
    UINT32                  Length,
    UINT32                  Level)
{

    /* Dump name and read/write flag */

    AcpiDmIndent (Level);
    AcpiOsPrintf ("Memory24 (%s,\n",
        AcpiGbl_RWDecode [Resource->Memory24.Flags & 1]);

    /* Dump the 4 contiguous WORD values */

    AcpiDmMemoryFields (&Resource->Memory24.Minimum, 16, Level);

    AcpiDmIndent (Level + 1);
    AcpiOsPrintf (")\n");
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiDmMemory32Descriptor
 *
 * PARAMETERS:  Resource            - Pointer to the resource descriptor
 *              Length              - Length of the descriptor in bytes
 *              Level               - Current source code indentation level
 *
 * RETURN:      None
 *
 * DESCRIPTION: Decode a Memory32 descriptor
 *
 ******************************************************************************/

void
AcpiDmMemory32Descriptor (
    AML_RESOURCE            *Resource,
    UINT32                  Length,
    UINT32                  Level)
{

    /* Dump name and read/write flag */

    AcpiDmIndent (Level);
    AcpiOsPrintf ("Memory32 (%s,\n",
        AcpiGbl_RWDecode [Resource->Memory32.Flags & 1]);

    /* Dump the 4 contiguous DWORD values */

    AcpiDmMemoryFields (&Resource->Memory32.Minimum, 32, Level);

    AcpiDmIndent (Level + 1);
    AcpiOsPrintf (")\n");
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiDmFixedMemory32Descriptor
 *
 * PARAMETERS:  Resource            - Pointer to the resource descriptor
 *              Length              - Length of the descriptor in bytes
 *              Level               - Current source code indentation level
 *
 * RETURN:      None
 *
 * DESCRIPTION: Decode a Fixed Memory32 descriptor
 *
 ******************************************************************************/

void
AcpiDmFixedMemory32Descriptor (
    AML_RESOURCE            *Resource,
    UINT32                  Length,
    UINT32                  Level)
{

    /* Dump name and read/write flag */

    AcpiDmIndent (Level);
    AcpiOsPrintf ("Memory32Fixed (%s,\n",
        AcpiGbl_RWDecode [Resource->FixedMemory32.Flags & 1]);

    AcpiDmIndent (Level + 1);
    AcpiDmDumpInteger32 (Resource->FixedMemory32.Address, "Address Base");

    AcpiDmIndent (Level + 1);
    AcpiDmDumpInteger32 (Resource->FixedMemory32.AddressLength, "Address Length");

    AcpiDmIndent (Level + 1);
    AcpiOsPrintf (")\n");
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiDmGenericRegisterDescriptor
 *
 * PARAMETERS:  Resource            - Pointer to the resource descriptor
 *              Length              - Length of the descriptor in bytes
 *              Level               - Current source code indentation level
 *
 * RETURN:      None
 *
 * DESCRIPTION: Decode a Generic Register descriptor
 *
 ******************************************************************************/

void
AcpiDmGenericRegisterDescriptor (
    AML_RESOURCE            *Resource,
    UINT32                  Length,
    UINT32                  Level)
{

    AcpiDmIndent (Level);
    AcpiOsPrintf ("Register (");
    AcpiDmAddressSpace (Resource->GenericReg.AddressSpaceId);
    AcpiOsPrintf ("\n");

    AcpiDmIndent (Level + 1);
    AcpiDmDumpInteger8 (Resource->GenericReg.BitWidth, "Register Bit Width");

    AcpiDmIndent (Level + 1);
    AcpiDmDumpInteger8 (Resource->GenericReg.BitOffset, "Register Bit Offset");

    AcpiDmIndent (Level + 1);
    AcpiDmDumpInteger64 (Resource->GenericReg.Address, "Register Address");

    /* Optional field for ACPI 3.0 */

    if (Resource->GenericReg.AccessSize)
    {
        AcpiDmIndent (Level + 1);
        AcpiOsPrintf ("0x%2.2X                // %s\n",
            Resource->GenericReg.AccessSize, "Access Size");
    }

    AcpiDmIndent (Level + 1);
    AcpiOsPrintf (")\n");
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiDmInterruptDescriptor
 *
 * PARAMETERS:  Resource            - Pointer to the resource descriptor
 *              Length              - Length of the descriptor in bytes
 *              Level               - Current source code indentation level
 *
 * RETURN:      None
 *
 * DESCRIPTION: Decode a extended Interrupt descriptor
 *
 ******************************************************************************/

void
AcpiDmInterruptDescriptor (
    AML_RESOURCE            *Resource,
    UINT32                  Length,
    UINT32                  Level)
{
    UINT32                  i;


    AcpiDmIndent (Level);
    AcpiOsPrintf ("Interrupt (%s, %s, %s, %s, ",
        AcpiGbl_ConsumeDecode [(Resource->ExtendedIrq.Flags & 1)],
        AcpiGbl_HEDecode [(Resource->ExtendedIrq.Flags >> 1) & 1],
        AcpiGbl_LLDecode [(Resource->ExtendedIrq.Flags >> 2) & 1],
        AcpiGbl_SHRDecode [(Resource->ExtendedIrq.Flags >> 3) & 1]);

    /*
     * The ResourceSource fields are optional and appear after the interrupt
     * list. Must compute length based on length of the list. First xrupt
     * is included in the struct (reason for -1 below)
     */
    AcpiDmResourceSource (Resource,
        sizeof (AML_RESOURCE_EXTENDED_IRQ) +
            (Resource->ExtendedIrq.InterruptCount - 1) * sizeof (UINT32),
        Resource->ExtendedIrq.ResourceLength);

    /* Dump the interrupt list */

    AcpiOsPrintf (")\n");
    AcpiDmIndent (Level);
    AcpiOsPrintf ("{\n");
    for (i = 0; i < Resource->ExtendedIrq.InterruptCount; i++)
    {
        AcpiDmIndent (Level + 1);
        AcpiOsPrintf ("0x%8.8X,\n",
            (UINT32) Resource->ExtendedIrq.Interrupts[i]);
    }

    AcpiDmIndent (Level);
    AcpiOsPrintf ("}\n");
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiDmVendorCommon
 *
 * PARAMETERS:  Name                - Descriptor name suffix
 *              ByteData            - Pointer to the vendor byte data
 *              Length              - Length of the byte data
 *              Level               - Current source code indentation level
 *
 * RETURN:      None
 *
 * DESCRIPTION: Decode a Vendor descriptor, both Large and Small
 *
 ******************************************************************************/

void
AcpiDmVendorCommon (
    char                    *Name,
    UINT8                   *ByteData,
    UINT32                  Length,
    UINT32                  Level)
{

    /* Dump descriptor name */

    AcpiDmIndent (Level);
    AcpiOsPrintf ("Vendor%s          // Length = 0x%.2X\n", Name, Length);

    /* Dump the vendor bytes */

    AcpiDmIndent (Level);
    AcpiOsPrintf ("{\n");

    AcpiDmDisasmByteList (Level + 1, ByteData, Length);

    AcpiDmIndent (Level);
    AcpiOsPrintf ("}\n");
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiDmVendorLargeDescriptor
 *
 * PARAMETERS:  Resource            - Pointer to the resource descriptor
 *              Length              - Length of the descriptor in bytes
 *              Level               - Current source code indentation level
 *
 * RETURN:      None
 *
 * DESCRIPTION: Decode a Vendor Large descriptor
 *
 ******************************************************************************/

void
AcpiDmVendorLargeDescriptor (
    AML_RESOURCE            *Resource,
    UINT32                  Length,
    UINT32                  Level)
{

    AcpiDmVendorCommon ("Long () ",
        ((UINT8 *) Resource) + sizeof (AML_RESOURCE_LARGE_HEADER),
        Length, Level);
}

#endif

