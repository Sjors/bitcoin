// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/descriptor_recombiner.h>

#include <script/descriptor.h>
#include <util/strencodings.h>

#include <algorithm>
#include <string_view>
#include <vector>

namespace wallet {
namespace {

std::string DescriptorWithoutChecksum(const std::string& descriptor)
{
    return descriptor.substr(0, descriptor.find('#'));
}

struct DescriptorPathParts {
    std::vector<std::string_view> fixed;
    std::vector<std::string_view> components;
};

DescriptorPathParts SplitDescriptorPathParts(const std::string& descriptor)
{
    DescriptorPathParts parts;
    size_t fixed_begin{0};
    for (size_t pos{0}; pos < descriptor.size(); ++pos) {
        if (descriptor[pos] != '/' || pos + 1 == descriptor.size() || !IsDigit(descriptor[pos + 1])) continue;

        const size_t component_begin{pos + 1};
        size_t component_end{component_begin};
        while (component_end < descriptor.size() && IsDigit(descriptor[component_end])) ++component_end;
        if (component_end < descriptor.size() && (descriptor[component_end] == 'h' || descriptor[component_end] == '\'')) {
            ++component_end;
        }

        parts.fixed.emplace_back(descriptor.data() + fixed_begin, component_begin - fixed_begin);
        parts.components.emplace_back(descriptor.data() + component_begin, component_end - component_begin);
        fixed_begin = component_end;
        pos = component_end - 1;
    }
    parts.fixed.emplace_back(descriptor.data() + fixed_begin, descriptor.size() - fixed_begin);
    return parts;
}

std::string ParsedDescriptorString(const Descriptor& descriptor, const FlatSigningProvider& provider, bool priv)
{
    std::string result;
    if (!priv || !descriptor.ToPrivateString(provider, result)) result = descriptor.ToString();
    return DescriptorWithoutChecksum(result);
}

std::optional<bool> IsInternal(const WalletDescInfo& info)
{
    if (info.internal.has_value()) return info.internal;

    const std::string descriptor{DescriptorWithoutChecksum(info.descriptor)};
    const bool receive{descriptor.find("/0/*") != std::string::npos};
    const bool change{descriptor.find("/1/*") != std::string::npos};
    if (receive == change) return std::nullopt;
    return change;
}

} // namespace

std::optional<std::string> RecombineDescriptorPair(const std::string& receive, const std::string& change)
{
    const std::string receive_without_checksum{DescriptorWithoutChecksum(receive)};
    const std::string change_without_checksum{DescriptorWithoutChecksum(change)};
    const DescriptorPathParts receive_parts{SplitDescriptorPathParts(receive_without_checksum)};
    const DescriptorPathParts change_parts{SplitDescriptorPathParts(change_without_checksum)};

    if (receive_parts.fixed != change_parts.fixed || receive_parts.components.size() != change_parts.components.size()) {
        return std::nullopt;
    }

    bool merged_component{false};
    std::string merged;
    for (size_t i{0}; i < receive_parts.components.size(); ++i) {
        merged += receive_parts.fixed[i];
        if (receive_parts.components[i] == change_parts.components[i]) {
            merged += receive_parts.components[i];
        } else {
            merged += '<';
            merged += receive_parts.components[i];
            merged += ';';
            merged += change_parts.components[i];
            merged += '>';
            merged_component = true;
        }
    }
    merged += receive_parts.fixed.back();
    if (!merged_component) return std::nullopt;

    FlatSigningProvider provider;
    std::string error;
    auto expanded{Parse(merged, provider, error, /*require_checksum=*/false)};
    const bool priv{!provider.keys.empty()};
    if (expanded.size() != 2 ||
        ParsedDescriptorString(*expanded[0], provider, priv) != receive_without_checksum ||
        ParsedDescriptorString(*expanded[1], provider, priv) != change_without_checksum) {
        return std::nullopt;
    }
    return merged;
}

std::map<std::string, RecombinedDescriptor> RecombineDescriptors(std::span<const WalletDescInfo> descriptors)
{
    std::vector<const WalletDescInfo*> receive_descriptors;
    std::vector<const WalletDescInfo*> change_descriptors;
    for (const auto& info : descriptors) {
        const auto internal{IsInternal(info)};
        if (!internal) continue;
        (*internal ? change_descriptors : receive_descriptors).push_back(&info);
    }

    std::vector<std::vector<std::optional<std::string>>> merged_descriptors(
        receive_descriptors.size(), std::vector<std::optional<std::string>>(change_descriptors.size()));
    std::vector<size_t> receive_matches(receive_descriptors.size());
    std::vector<size_t> change_matches(change_descriptors.size());
    for (size_t receive_index{0}; receive_index < receive_descriptors.size(); ++receive_index) {
        for (size_t change_index{0}; change_index < change_descriptors.size(); ++change_index) {
            auto merged{RecombineDescriptorPair(receive_descriptors[receive_index]->descriptor, change_descriptors[change_index]->descriptor)};
            if (!merged) continue;
            merged_descriptors[receive_index][change_index] = std::move(merged);
            ++receive_matches[receive_index];
            ++change_matches[change_index];
        }
    }

    std::map<std::string, RecombinedDescriptor> result;
    for (size_t receive_index{0}; receive_index < receive_descriptors.size(); ++receive_index) {
        if (receive_matches[receive_index] != 1) continue;
        const auto match{std::ranges::find_if(merged_descriptors[receive_index], [](const auto& merged) { return merged.has_value(); })};
        const size_t change_index{static_cast<size_t>(std::distance(merged_descriptors[receive_index].begin(), match))};
        if (change_matches[change_index] != 1) continue;

        result.emplace(receive_descriptors[receive_index]->descriptor, RecombinedDescriptor{**match, /*internal=*/false});
        result.emplace(change_descriptors[change_index]->descriptor, RecombinedDescriptor{**match, /*internal=*/true});
    }
    return result;
}

} // namespace wallet
