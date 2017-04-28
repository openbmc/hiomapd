#pragma once

#include "config.h"
#include <fstream>

namespace openpower
{
namespace flash
{

/** @class Location
 *
 *  @brief Provides APIs to retrieve the location of flash partition
 *         related files.
 */
class Location
{
    public:
        /** @brief default ctor
         */
        Location():
            tocFile(PARTITION_HDR_FILE),
            dir(PARTITION_FILES_LOC)
        {
        }

        /** @brief ctor
         *
         *  @param[in] tocFile - table of contents file path
         *  @param[in] dir - directory housing partition files
         */
        Location(const std::string& tocFile,
                 const std::string& dir):
            tocFile(tocFile),
            dir(dir)
        {
        }

        Location(const Location&) = delete;
        Location& operator=(const Location&) = delete;
        Location(Location&&) = delete;
        Location& operator=(Location&&) = delete;
        ~Location() = default;

        /** @brief Get path of directory housing partition files
         *
         *  @return const std::string& - directory housing partition files
         */
        const std::string& directory() const
        {
            return dir;
        }

        /** @brief Get table of contents file
         *
         *  @return std::ifstream& - table of contents file object
         */
        std::ifstream& file()
        {
            return tocFile;
        }

    private:
        std::ifstream tocFile;
        std::string dir;
};

}
}
