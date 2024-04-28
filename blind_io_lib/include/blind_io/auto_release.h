////////////////////////////////////////////////////////////////////////////////
//         Distributed under the Boost Software License, Version 1.0.         //
//            (See accompanying file LICENSE or copy at                       //
//                 https://www.boost.org/LICENSE_1_0.txt)                     //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include <functional>
#include <ranges>

namespace bio
{

/**
 * Generic RAII class for taking ownership of a "handle" type resources and releasing it when this class goes out of
 * scope.
 *
 * The resources themselves are assumed to be handles i.e. trivially copyable
 */
template <class T, T Invalid = T{}>
class AutoRelease
{
  public:
    /**
     * Construct an empty AutoRelease object that doesn't own any object.
     */
    AutoRelease()
        : AutoRelease(Invalid)
    {
    }

    /**
     * Construct a new AutoRelease which takes ownership of a resource, with an optional deleter.
     *
     * @param obj
     *   Resource to own.
     *
     * @param deleter
     *   Function to release resource at end of scope.
     */
    explicit AutoRelease(T obj, std::function<void(T)> deleter = nullptr)
        : obj_(obj)
        , deleter_(deleter)
    {
    }

    AutoRelease(const AutoRelease &) = delete;
    AutoRelease &operator=(const AutoRelease &) = delete;

    /**
     * Move constructor. Steals ownership from supplied object.
     *
     * @param other
     *   Object to move construct from.
     */
    AutoRelease(AutoRelease &&other)
        : AutoRelease()
    {
        swap(other);
    }

    /**
     * Move assignment. Steals ownership from supplied object.
     *
     * @param other
     *   Object to move assign from.
     */
    AutoRelease &operator=(AutoRelease &&other)
    {
        AutoRelease new_obj{std::move(other)};
        swap(new_obj);

        return *this;
    }

    /**
     * Release resource with supplied deleter.
     */
    ~AutoRelease()
    {
        if ((obj_ != Invalid) && deleter_)
        {
            deleter_(obj_);
        }
    }

    /**
     * Get the managed resource.
     *
     * @returns
     *   Managed resource.
     */
    T get() const
    {
        return obj_;
    }

    /**
     * Cast operator.
     *
     * @returns
     *   Managed resource.
     */
    operator T() const
    {
        return obj_;
    }

    /**
     * Get if this object manages a resource.
     *
     * @returns
     *   True if this object managed a resource, false otherwise.
     */
    explicit operator bool() const
    {
        return obj_ != Invalid;
    }

    bool operator==(const AutoRelease &) const = default;
    bool operator!=(const AutoRelease &) const = default;

    /**
     * Swap this object with another.
     *
     * @param other
     *   Object to swap with.
     */
    void swap(AutoRelease &other)
    {
        std::ranges::swap(obj_, other.obj_);
        std::ranges::swap(deleter_, other.deleter_);
    }

  private:
    /** Managed resource. */
    T obj_;

    /** Resource delete function. */
    std::function<void(T)> deleter_;
};

/**
 * Swap two AutoRelease objects.
 *
 * @param ar1
 *   First object to swap.
 *
 * @param ar2
 *   Second object to swap.
 */
template <class T, T Invalid>
void swap(AutoRelease<T, Invalid> &ar1, AutoRelease<T, Invalid> &ar2)
{
    ar1.swap(ar2);
}

}