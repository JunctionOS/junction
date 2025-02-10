/* vdso.ld -- Custom linker script for vDSO with one loadable segment */

OUTPUT_FORMAT(elf64-x86-64)

SECTIONS
{
  /* Set the base address. */
   . = SIZEOF_HEADERS;

   .hash    : { *(.hash) }       :text
   .gnu.hash   : { *(.gnu.hash) }
   .dynsym     : { *(.dynsym) }
   .dynstr     : { *(.dynstr) }
   .gnu.version   : { *(.gnu.version) }
   .gnu.version_d : { *(.gnu.version_d) }
   .gnu.version_r : { *(.gnu.version_r) }

   .dynamic : { *(.dynamic) }    :text :dynamic

   .rodata     : {
      *(.rodata*)
      *(.data*)
      *(.sdata*)
      *(.got.plt) *(.got)
      *(.gnu.linkonce.d.*)
      *(.bss*)
      *(.dynbss*)
      *(.gnu.linkonce.b.*)
   }                 :text


   /DISCARD/ : {
      *(.note.gnu.property)
   }
   .note    : { *(.note.*) }     :text :note

   .eh_frame_hdr  : { *(.eh_frame_hdr) }     :text :eh_frame_hdr
   .eh_frame   : { KEEP (*(.eh_frame)) }  :text

   .text    : {
      *(.text*)
   }                 :text =0x90909090,

}

PHDRS
{
   text     PT_LOAD     FLAGS(5) FILEHDR PHDRS; /* PF_R|PF_X */
   dynamic     PT_DYNAMIC  FLAGS(4);      /* PF_R */
   note     PT_NOTE     FLAGS(4);      /* PF_R */
   eh_frame_hdr   PT_GNU_EH_FRAME;
}
