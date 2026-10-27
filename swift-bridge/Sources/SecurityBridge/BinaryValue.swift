import Foundation
import Security
import SecurityBridgeABI

final class BridgeValueBox {
    let raw: UnsafeMutablePointer<SecurityBridgeValue>
    private var bytes: UnsafeMutablePointer<UInt8>?
    private var values: UnsafeMutablePointer<SecurityBridgeValue>?
    private var entries: UnsafeMutablePointer<SecurityBridgeEntry>?
    private var children: [BridgeValueBox] = []

    init?(_ object: Any, depth: Int = 0) {
        guard depth <= 128 else {
            return nil
        }
        raw = .allocate(capacity: 1)
        raw.initialize(to: SecurityBridgeValue())
        switch object {
        case is NSNull:
            raw.pointee.tag = UInt32(SECURITY_VALUE_NULL)
        case let value as String:
            setBytes(Array(value.utf8), tag: SECURITY_VALUE_STRING)
        case let value as NSNumber:
            if CFGetTypeID(value) == CFBooleanGetTypeID() {
                raw.pointee.tag = UInt32(SECURITY_VALUE_BOOL)
                raw.pointee.unsigned_integer = value.boolValue ? 1 : 0
            } else {
                let type = String(cString: value.objCType)
                if type == "f" || type == "d" {
                    raw.pointee.tag = UInt32(SECURITY_VALUE_REAL)
                    raw.pointee.real = value.doubleValue
                } else if ["C", "S", "I", "L", "Q"].contains(type) {
                    raw.pointee.tag = UInt32(SECURITY_VALUE_UNSIGNED)
                    raw.pointee.unsigned_integer = value.uint64Value
                } else {
                    raw.pointee.tag = UInt32(SECURITY_VALUE_INTEGER)
                    raw.pointee.integer = value.int64Value
                }
            }
        case let value as Data:
            setBytes(Array(value), tag: SECURITY_VALUE_DATA)
        case let value as Date:
            raw.pointee.tag = UInt32(SECURITY_VALUE_DATE)
            raw.pointee.real = value.timeIntervalSince1970
        case let value as URL:
            setBytes(Array(value.absoluteString.utf8), tag: SECURITY_VALUE_URL)
        case let items as [Any]:
            raw.pointee.tag = UInt32(SECURITY_VALUE_ARRAY)
            raw.pointee.length = items.count
            values = .allocate(capacity: max(items.count, 1))
            for (index, item) in items.enumerated() {
                guard let child = BridgeValueBox(item, depth: depth + 1) else {
                    return nil
                }
                children.append(child)
                values!.advanced(by: index).initialize(to: child.raw.pointee)
            }
            raw.pointee.values = UnsafePointer(values)
        case let dictionary as NSDictionary:
            var items: [String: Any] = [:]
            for (key, value) in dictionary {
                items[String(describing: key)] = value
            }
            raw.pointee.tag = UInt32(SECURITY_VALUE_OBJECT)
            raw.pointee.length = items.count
            entries = .allocate(capacity: max(items.count, 1))
            for (index, key) in items.keys.sorted().enumerated() {
                guard let keyValue = BridgeValueBox(key, depth: depth + 1),
                      let child = BridgeValueBox(items[key]!, depth: depth + 1)
                else {
                    return nil
                }
                children.append(keyValue)
                children.append(child)
                let buffer = SecurityBridgeBuffer(data: keyValue.raw.pointee.bytes, length: keyValue.raw.pointee.length)
                entries!.advanced(by: index).initialize(to: SecurityBridgeEntry(key: buffer, value: child.raw.pointee))
            }
            raw.pointee.entries = UnsafePointer(entries)
        default:
            guard let child = BridgeValueBox(
                securityObjectValue(object as AnyObject) ?? String(describing: object),
                depth: depth + 1
            ) else {
                return nil
            }
            children.append(child)
            raw.pointee = child.raw.pointee
        }
    }

    private func setBytes(_ source: [UInt8], tag: Int) {
        bytes = .allocate(capacity: max(source.count, 1))
        for (index, byte) in source.enumerated() {
            bytes!.advanced(by: index).initialize(to: byte)
        }
        raw.pointee.tag = UInt32(tag)
        raw.pointee.bytes = UnsafePointer(bytes)
        raw.pointee.length = source.count
    }

    deinit {
        bytes?.deallocate()
        values?.deallocate()
        entries?.deallocate()
        raw.deinitialize(count: 1)
        raw.deallocate()
    }
}

func valueHandle(_ object: Any) -> UnsafeMutableRawPointer? {
    guard let value = BridgeValueBox(object) else {
        return nil
    }
    return Unmanaged.passRetained(value).toOpaque()
}

@_cdecl("security_value_get")
public func securityValueGet(_ handle: UnsafeMutableRawPointer?) -> UnsafePointer<SecurityBridgeValue>? {
    guard let handle,
          let value = Unmanaged<AnyObject>.fromOpaque(handle).takeUnretainedValue() as? BridgeValueBox
    else {
        return nil
    }
    return UnsafePointer(value.raw)
}

func valueObject(from pointer: UnsafePointer<SecurityBridgeValue>?, depth: Int = 0) -> Any? {
    guard let pointer, depth <= 128 else {
        return nil
    }
    let value = pointer.pointee
    guard value.reserved == 0, value.length <= Int.max else {
        return nil
    }
    let count = Int(value.length)
    switch Int(value.tag) {
    case SECURITY_VALUE_NULL:
        return NSNull()
    case SECURITY_VALUE_BOOL:
        return value.unsigned_integer <= 1 ? NSNumber(value: value.unsigned_integer != 0) : nil
    case SECURITY_VALUE_INTEGER:
        return NSNumber(value: value.integer)
    case SECURITY_VALUE_UNSIGNED:
        return NSNumber(value: value.unsigned_integer)
    case SECURITY_VALUE_REAL:
        return NSNumber(value: value.real)
    case SECURITY_VALUE_STRING, SECURITY_VALUE_URL:
        guard count == 0 || value.bytes != nil,
              let text = String(bytes: UnsafeBufferPointer(start: value.bytes, count: count), encoding: .utf8)
        else {
            return nil
        }
        if Int(value.tag) == SECURITY_VALUE_URL {
            return URL(string: text)
        }
        return text
    case SECURITY_VALUE_DATA:
        guard count == 0 || value.bytes != nil else {
            return nil
        }
        return Data(UnsafeBufferPointer(start: value.bytes, count: count))
    case SECURITY_VALUE_DATE:
        return Date(timeIntervalSince1970: value.real)
    case SECURITY_VALUE_ARRAY:
        guard count == 0 || value.values != nil else {
            return nil
        }
        var result: [Any] = []
        for index in 0 ..< count {
            guard let item = valueObject(from: value.values?.advanced(by: index), depth: depth + 1) else {
                return nil
            }
            result.append(item)
        }
        return result
    case SECURITY_VALUE_OBJECT:
        guard count == 0 || value.entries != nil else {
            return nil
        }
        var result: [String: Any] = [:]
        for index in 0 ..< count {
            let entry = value.entries!.advanced(by: index)
            let key = entry.pointee.key
            guard key.length <= Int.max, key.length == 0 || key.data != nil,
                  let name = String(bytes: UnsafeBufferPointer(start: key.data, count: Int(key.length)), encoding: .utf8),
                  let item = withUnsafePointer(to: entry.pointee.value, {
                      valueObject(from: $0, depth: depth + 1)
                  })
            else {
                return nil
            }
            result[name] = item
        }
        return result
    default:
        return nil
    }
}

func valueStringArray(from pointer: UnsafePointer<SecurityBridgeValue>?) -> [String]? {
    guard let values = valueObject(from: pointer) as? [Any] else {
        return nil
    }
    let strings = values.compactMap { $0 as? String }
    return strings.count == values.count ? strings : nil
}

func valueDataArray(from pointer: UnsafePointer<SecurityBridgeValue>?) -> [Data]? {
    guard let values = valueObject(from: pointer) as? [Any] else {
        return nil
    }
    let data = values.compactMap(valueData(from:))
    return data.count == values.count ? data : nil
}

func keyUsageArray(from pointer: UnsafePointer<SecurityBridgeValue>?) -> [CFString]? {
    guard let names = valueStringArray(from: pointer) else {
        return nil
    }
    let usages = names.compactMap { name -> CFString? in
        switch name {
        case "can_encrypt": return kSecAttrCanEncrypt
        case "can_decrypt": return kSecAttrCanDecrypt
        case "can_derive": return kSecAttrCanDerive
        case "can_sign": return kSecAttrCanSign
        case "can_verify": return kSecAttrCanVerify
        case "can_wrap": return kSecAttrCanWrap
        case "can_unwrap": return kSecAttrCanUnwrap
        default: return nil
        }
    }
    return usages.count == names.count ? usages : nil
}
