SECTIONS
{
	.text ALIGN( 1 ) : SUBALIGN( 1 )
	{
		*( .text$A )
		*( .text$B )
		*( .rdata* )
		*( .text$C )
	}
}
