/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#include "aesd-circular-buffer.h"

/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
            size_t char_offset, size_t *entry_offset_byte_rtn )
{
    // If the character offset is 0, return the first entry
    if (char_offset == 0)
    {
        *entry_offset_byte_rtn = 0;
        return &buffer->entry[buffer->out_offs];
    }

    // Initialize variables
    uint8_t search_index = buffer->out_offs;
    size_t search_offset = 0;

    // Loop through buffer entries
    while (1)
    {
        // Increase search offset by current entry size
        search_offset += buffer->entry[search_index].size;

        // If search offset exceeds character offset, calculate entry offset byte
        if (search_offset > char_offset)
        {
            // Calculate entry offset byte
            *entry_offset_byte_rtn = char_offset - (search_offset - buffer->entry[search_index].size);
            return &buffer->entry[search_index];
        }

        // Move to the next entry and wrap around if necessary
        search_index++;
        search_index %= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;

        // Break if we reach the in_offs (end of buffer)
        if (search_index == buffer->in_offs)
        {
            break;
        }
    }

    // If offset not found, return NULL
    return NULL;
}


/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
const char *aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    const char *ret_ptr = NULL;
    if ((buffer == NULL) || (add_entry == NULL))
    {
        return ret_ptr;
    }

    if (buffer->full)
    {
        ret_ptr = buffer->entry[buffer->in_offs].buffptr;
    }

    buffer->entry[buffer->in_offs].buffptr = add_entry->buffptr;
    buffer->entry[buffer->in_offs].size = add_entry->size;
    buffer->in_offs++;
    // Buffer wrap around
    buffer->in_offs %= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    // Check if the buffer is full
    if(!buffer->full)
    {
        if(buffer->in_offs == buffer->out_offs)
        {
            buffer->full = true;
        }
    }
    else
    {
        buffer->out_offs++;
        buffer->out_offs %= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }
    return ret_ptr;
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}
