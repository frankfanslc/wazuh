#ifndef _CON_T_H
#define _CON_T_H

#include "rxcpp/rx.hpp"
#include "json/json.hpp"

namespace builder::internals
{

/**
 * @brief A connectable is a structure which help us build the RXCPP graph when 
 * our assets are in the graph.
 * 
 * @tparam Observable 
 */
template <class Observable> struct Connectable
{
    /**
     * @brief An operation is a function which will generate
     * an observable with the apropriate transformations and filters 
     * generated by the asset building process.
     */
    using Op_t = std::function<Observable(const Observable &)>;
    Op_t m_op;

    /**
     * @brief Used to distinguish between connectables. Also for debugging purposes.
     * It is derived from the name of the asset it contains de operation for.
     */
    std::string m_name;

    /**
     * @brief The name of the parents of this connectable, derived directly
     * from the assets definition.
     */
    std::vector<std::string> m_parents;

    /**
     * @brief The parents' outputs are this connectable inputs. Each connecatble
     * must merge their parents' output as a single input for this connectable
     * operation.
     */
    std::vector<Observable> m_inputs;

    
    /**
     * @brief Construct a new Connectable object from its components.
     * 
     * @param n name of the connectable
     * @param p vector of parents names
     * @param o the operation this connectable must do to the input stream.
     */
    Connectable(std::string n, std::vector<std::string> p, Op_t o) : m_name(n), m_parents(p), m_op(o){};

    /**
     * @brief Construct a new Connectable object just from its name. It will use
     * a default passthough operation which allow us to create nodes whose sole 
     * purpose is to facilitate the graph construction.
     * 
     * @param n name of the connectable
     */
    Connectable(std::string n) : m_name(n)
    {
        m_op = [](Observable o) { return o; };
    };

    /**
     * @brief Adds an input stream to this connectable
     * 
     * @param obs input stream
     */
    void addInput(Observable obs)
    {
        inputs.push_back(obs);
    }
    /**
     * @brief Connects an input stream with the operation of this
     * connectable and returns an observable with the operation already
     * attached.
     * 
     * @param input 
     * @return Observable 
     */
    Observable connect(const Observable & input)
    {
        return m_op(input);
    }

    /**
     * @brief Merge all inputs of this node into a single stream and return
     * an obserbable with the operation already attached.
     * 
     * @return Observable 
     */
    Observable connect()
    {
        if (inputs.size() > 1)
        {
            return op(rxcpp::observable<>::iterate(inputs).flat_map([](Observable o) { return o; }));
        }
        return op(inputs[0]);
    }

    /**
     * @brief Operatos defined so Connectables can be stored on maps and sets as keys.
     * 
     */

    friend inline bool operator<(const Connectable & lhs, const Connectable & rhs)
    {
        return lhs.name < rhs.name;
    }

    friend inline std::ostream & operator<<(std::ostream & os, const Connectable & rhs)
    {
        os << rhs.name;
        return os;
    }

    friend inline bool operator!=(const Connectable & l, const Connectable & r)
    {
        return l.name != r.name;
    }

    friend inline bool operator==(const Connectable & l, const Connectable & r)
    {
        return l.name == r.name;
    }


};
} // namespace builder::internals
#endif