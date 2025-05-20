#pragma once

#include <windows.h>
#include <winternl.h>
#include <cstdint>
#include <string>

namespace jmport
{
	inline PEB* get_proc_env_block( )
	{
#ifdef _M_X64
		return reinterpret_cast< PEB* >( __readgsqword( 0x60 ) );
#else
		return reinterpret_cast< PEB* >( __readfsdword( 0x30 ) );
#endif
	}

	class address
	{
	public:
		address( uintptr_t address = 0 ) : m_address( address ) { }
		address( void* address ) : m_address( reinterpret_cast< uintptr_t >( address ) ) { }
		address( const address& other ) : m_address( other.m_address ) { }

	public:
		template<typename t>
		t as( ) const
		{
			return t( m_address );
		}

		address add( size_t offset ) const
		{
			return address( m_address + offset );
		}

		address sub( size_t offset ) const
		{
			return address( m_address - offset );
		}

	private:
		uintptr_t m_address;
	};

	class module
	{
	public:
		module( const wchar_t* module_name )
		{
			auto module_list = &get_proc_env_block( )->Ldr->InMemoryOrderModuleList;
			for ( auto current_entry = module_list->Flink; current_entry != module_list; current_entry = current_entry->Flink )
			{
				auto current_ldr_entry = CONTAINING_RECORD( current_entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks );
				if ( !current_ldr_entry )
					continue;

				if ( !module_name )
				{
					m_base_addr = current_ldr_entry->DllBase;
					break;
				}

				auto full_dll_name = std::wstring( current_ldr_entry->FullDllName.Buffer );
				for ( wchar_t& c : full_dll_name )
					c = std::tolower( c );

				if ( full_dll_name.find( module_name ) != std::wstring::npos )
				{
					m_base_addr = current_ldr_entry->DllBase;
					break;
				}
			}
		}

	public:
		address get_base( ) const
		{
			return m_base_addr;
		}

		IMAGE_DOS_HEADER* get_dos_header( ) const
		{
			if ( !m_base_addr.as<uintptr_t>( ) )
				return 0;

			return reinterpret_cast< IMAGE_DOS_HEADER* >( m_base_addr.as<uintptr_t>( ) );
		}

		IMAGE_NT_HEADERS* get_nt_headers( ) const
		{
			if ( !m_base_addr.as<uintptr_t>( ) )
				return 0;

			return reinterpret_cast< IMAGE_NT_HEADERS* >( m_base_addr.as<uintptr_t>( ) + get_dos_header( )->e_lfanew );
		}

		address operator []( const char* function_name )
		{
			if ( !m_base_addr.as<uintptr_t>( ) )
				return address( );

			auto nt_headers = get_nt_headers( );
			if ( nt_headers->Signature != IMAGE_NT_SIGNATURE )
				return address( );

			auto export_directory = nt_headers->OptionalHeader.DataDirectory[ 0 ];
			if ( !export_directory.Size )
				return address( );

			auto export_data = m_base_addr.add( export_directory.VirtualAddress ).as<IMAGE_EXPORT_DIRECTORY*>( );
			if ( !export_data )
				return address( );

			auto name_table = m_base_addr.add( export_data->AddressOfNames ).as< uint32_t* >( );
			auto ordinal_table = m_base_addr.add( export_data->AddressOfNameOrdinals ).as< uint16_t* >( );
			auto func_table = m_base_addr.add( export_data->AddressOfFunctions ).as< uint32_t* >( );

			for ( int i = 0; i < export_data->NumberOfNames; i++ )
			{
				auto current_func_name = m_base_addr.add( name_table[ i ] ).as< const char* >( );
				auto current_func_addr = m_base_addr.add( func_table[ ordinal_table[ i ] ] );

				if ( !strcmp( current_func_name, function_name ) )
					return current_func_addr;
			}

			return address( );
		}

	private:
		address m_base_addr;
	};
}